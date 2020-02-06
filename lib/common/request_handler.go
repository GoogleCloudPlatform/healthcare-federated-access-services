// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package common

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	glog "github.com/golang/glog" /* copybara-comment */
	"github.com/golang/protobuf/jsonpb" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
	"github.com/gorilla/mux" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/srcutil" /* copybara-comment: srcutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
)

const (
	defaultNameField = "name"
	PlaceholderName  = "-"
)

var (
	NameRE              = regexp.MustCompile(`^[A-Za-z][-_A-Za-z0-9\.]{1,30}[A-Za-z0-9]$`)
	LongNameRE          = regexp.MustCompile(`^[A-Za-z][-_A-Za-z0-9\.]{1,46}[A-Za-z0-9]$`)
	PlaceholderOrNameRE = regexp.MustCompile(`^(-|[A-Za-z][-_A-Za-z0-9\.]{1,30}[A-Za-z0-9])$`)
	TokenNameRE         = regexp.MustCompile(`^[-_\.A-Za-z0-9]{1,64}$`)
	longNameFields      = map[string]bool{
		"realm": true,
	}
	SubRE = regexp.MustCompile(`^[A-Za-z0-9][-_A-Za-z0-9\.]{0,64}@?[-_A-Za-z0-9\.]{0,128}[A-Za-z0-9]$`)
	JTIRE = regexp.MustCompile(`^[A-Za-z0-9][-_A-Za-z0-9\.]{0,64}[A-Za-z0-9]$`)
)

type ServiceInterface interface {
	GetStore() storage.Store
}

type HandlerFactory struct {
	TypeName            string
	NameField           string
	PathPrefix          string
	HasNamedIdentifiers bool
	NameChecker         map[string]*regexp.Regexp
	NewHandler          func(w http.ResponseWriter, r *http.Request) HandlerInterface
}

type HandlerInterface interface {
	Setup(tx storage.Tx) (int, error)
	// TODO: Have LookupItem() return an error instead, so different errors can be handled
	// properly, e.g. permission denied error vs. lookup error.
	LookupItem(name string, vars map[string]string) bool
	NormalizeInput(name string, vars map[string]string) error
	Get(name string) error
	Post(name string) error
	Put(name string) error
	Patch(name string) error
	Remove(name string) error
	CheckIntegrity() *status.Status
	Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error
}

func MakeHandler(s ServiceInterface, hri *HandlerFactory) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		nameVar := defaultNameField
		if len(hri.NameField) > 0 {
			nameVar = hri.NameField
		}
		name := vars[nameVar]

		for k, v := range vars {
			if err := CheckName(k, v, hri.NameChecker); err != nil {
				HandleError(http.StatusBadRequest, err, w)
				return
			}
		}
		tx, err := s.GetStore().Tx(r.Method != http.MethodGet)
		if err != nil {
			HandleError(http.StatusServiceUnavailable, fmt.Errorf("service dependencies not available; try again later"), w)
			return
		}
		defer tx.Finish()

		hi := hri.NewHandler(w, r)
		status, err := hi.Setup(tx)
		if err != nil {
			HandleError(status, err, w)
			return
		}
		itemOk := hi.LookupItem(name, vars)
		typ := hri.TypeName
		desc := r.Method + " " + typ

		if !itemOk && r.Method != http.MethodPost {
			var err error
			if hri.HasNamedIdentifiers {
				err = fmt.Errorf("%s not found: %q", typ, name)
			} else {
				err = fmt.Errorf("%s not found", typ)
			}
			HandleError(http.StatusNotFound, err, w)
			return
		}

		switch r.Method {
		case http.MethodGet:
			if err := hi.NormalizeInput(name, vars); err != nil {
				HandleError(http.StatusBadRequest, err, w)
				return
			}
			if err := hi.Get(name); err != nil {
				HandleError(http.StatusBadRequest, err, w)
				return
			}
		case http.MethodPost:
			if itemOk {
				HandleError(http.StatusConflict, fmt.Errorf("%s already exists: %q", typ, name), w)
				return
			}
			if err := hi.NormalizeInput(name, vars); err != nil {
				HandleError(http.StatusBadRequest, err, w)
				return
			}
			if err = hi.Post(name); err != nil {
				HandleError(http.StatusBadRequest, err, w)
				return
			}
			if stat := hi.CheckIntegrity(); stat != nil {
				tx.Rollback()
				handleIntegrityError(stat, w)
				return
			}
			if err := hi.Save(tx, name, vars, desc, typ); err != nil {
				tx.Rollback()
				HandleError(http.StatusInternalServerError, err, w)
				return
			}
		case http.MethodPut:
			fallthrough
		case http.MethodPatch:
			if err := hi.NormalizeInput(name, vars); err != nil {
				HandleError(http.StatusBadRequest, err, w)
				return
			}
			if r.Method == http.MethodPut {
				err = hi.Put(name)
			} else {
				err = hi.Patch(name)
			}
			if err != nil {
				tx.Rollback()
				HandleError(http.StatusBadRequest, err, w)
				return
			}
			if stat := hi.CheckIntegrity(); stat != nil {
				tx.Rollback()
				handleIntegrityError(stat, w)
				return
			}
			if err := hi.Save(tx, name, vars, desc, typ); err != nil {
				tx.Rollback()
				HandleError(http.StatusInternalServerError, err, w)
				return
			}
		case http.MethodDelete:
			if err := hi.Remove(name); err != nil {
				HandleError(http.StatusBadRequest, err, w)
				return
			}
			if stat := hi.CheckIntegrity(); stat != nil {
				tx.Rollback()
				handleIntegrityError(stat, w)
				return
			}
			if err := hi.Save(tx, name, vars, desc, typ); err != nil {
				tx.Rollback()
				HandleError(http.StatusInternalServerError, err, w)
				return
			}
		default:
			HandleError(http.StatusBadRequest, fmt.Errorf("request method not supported: %q", r.Method), w)
			return
		}
	}
}

// GetParam returns a URL query parameter value.
func GetParam(r *http.Request, name string) string {
	if set, ok := r.Form[name]; ok && len(set) > 0 {
		return set[0]
	}
	return ""
}

// ExtractIntParam return an integer parameter value, or 0 if missing or invalid.
func ExtractIntParam(r *http.Request, name string) int {
	v, err := strconv.Atoi(GetParam(r, name))
	if err != nil {
		return 0
	}
	return v
}

// GetParamOrDefault returns a URL query parameter value or a default value if it is not present or empty.
func GetParamOrDefault(r *http.Request, name, defaultValue string) string {
	out := GetParam(r, name)
	if out == "" {
		return defaultValue
	}
	return out
}

// GetParamList returns a list of URL query parameter values.
func GetParamList(r *http.Request, name string) []string {
	if set, ok := r.Form[name]; ok {
		return set
	}
	return nil
}

func HandleError(num int, err error, w http.ResponseWriter) {
	AddCorsHeaders(w)
	w.WriteHeader(num)
	msg := fmt.Sprintf("%d request error: %v\n", num, err)
	w.Write([]byte(msg))
	glog.Infof(msg)
}

func handleIntegrityError(stat *status.Status, w http.ResponseWriter) {
	if len(stat.Details()) > 0 {
		httputil.WriteStatus(w, stat)
		return
	}
	HandleError(FromCode(stat.Code()), fmt.Errorf("%s", stat.Message()), w)
}

func AddCorsHeaders(w http.ResponseWriter) {
	httputil.WriteCorsHeaders(w)
}

func GetRequest(pb proto.Message, r *http.Request) error {
	if err := jsonpb.Unmarshal(r.Body, pb); err != nil && err != io.EOF {
		return err
	}
	return nil
}

// IsJSON returns true when the data format is JSON
func IsJSON(str string) bool {
	return str == "application/json" || str == "JSON" || str == "json"
}

// SendResponse puts a proto message in the response.
func SendResponse(resp proto.Message, w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	AddCorsHeaders(w)
	ma := jsonpb.Marshaler{}
	return ma.Marshal(w, resp)
}

// SendHTML writes a "text/html" type string to the ResponseWriter.
func SendHTML(html string, w http.ResponseWriter) {
	AddCorsHeaders(w)
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// SendJSONResponse sends headers and a response in string format.
func SendJSONResponse(json string, w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	AddCorsHeaders(w)
	_, err := w.Write([]byte(json))
	return err
}

// SendRedirect forwards user session to the URL provided.
func SendRedirect(url string, r *http.Request, w http.ResponseWriter) {
	AddCorsHeaders(w)
	url = strings.Replace(url, "%2526", "&", -1)
	url = strings.Replace(url, "%253F", "?", -1)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// DecodeJSONFromBody decodes json in http request/response body.
func DecodeJSONFromBody(body io.ReadCloser, o interface{}) error {
	defer body.Close()

	b, err := ioutil.ReadAll(body)
	if err != nil {
		return fmt.Errorf("ioutil.ReadAll failed: %v", err)
	}

	err = json.Unmarshal(b, o)
	if err != nil {
		return fmt.Errorf("json.Unmarshal(%s) failed: %v", string(b), err)
	}
	return nil
}

// EncodeJSONToResponse encode o to json to http response body.
// No Cors and no-cache header will apply.
func EncodeJSONToResponse(w http.ResponseWriter, status int, o interface{}) error {
	b, err := json.Marshal(o)
	if err != nil {
		return fmt.Errorf("json.Marshal(%v) failed: %v", o, err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, err = w.Write(b)
	return err
}

// CheckName checks name following the given rule.
func CheckName(field, name string, rem map[string]*regexp.Regexp) error {
	if len(name) == 0 {
		return fmt.Errorf("invalid %s: empty", field)
	}
	re := NameRE
	if _, ok := longNameFields[field]; ok {
		re = LongNameRE
	}
	if rem != nil {
		if mre, ok := rem[field]; ok {
			re = mre
		}
	}
	if !re.Match([]byte(name)) {
		return fmt.Errorf("invalid %s: %q is too long, too short, or contains invalid characters", field, name)
	}
	return nil
}

// LoadFile reads a file in as a string from I/O.
func LoadFile(filename string) (string, error) {
	bytes, err := ioutil.ReadFile(srcutil.Path(filename))
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}
