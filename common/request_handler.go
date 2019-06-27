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
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/storage"

	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
	"github.com/gorilla/mux"
)

const (
	defaultNameField = "name"
	PlaceholderName  = "-"
)

var (
	NameRE              = regexp.MustCompile(`^[A-Za-z][-_A-Za-z0-9\.]{1,30}[A-Za-z0-9]$`)
	LongNameRE          = regexp.MustCompile(`^[A-Za-z][-_A-Za-z0-9\.]{1,46}[A-Za-z0-9]$`)
	PlaceholderOrNameRE = regexp.MustCompile(`^(-|[A-Za-z][-_A-Za-z0-9\.]{1,30}[A-Za-z0-9])$`)
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
	IsAdmin             bool
	NameChecker         map[string]*regexp.Regexp
	NewHandler          func(w http.ResponseWriter, r *http.Request) HandlerInterface
}

type HandlerInterface interface {
	Setup(tx storage.Tx, isAdmin bool) (int, error)
	// TODO: Have LookupItem() return an error instead, so different errors can be handled
	// properly, e.g. permission denied error vs. lookup error.
	LookupItem(name string, vars map[string]string) bool
	NormalizeInput(name string, vars map[string]string) error
	Get(name string) error
	Post(name string) error
	Put(name string) error
	Patch(name string) error
	Remove(name string) error
	CheckIntegrity() (proto.Message, int, error)
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
		status, err := hi.Setup(tx, hri.IsAdmin)
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
			if results, status, err := hi.CheckIntegrity(); err != nil {
				tx.Rollback()
				handleIntegrityError(w, results, status, err)
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
			if results, status, err := hi.CheckIntegrity(); err != nil {
				tx.Rollback()
				handleIntegrityError(w, results, status, err)
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
			if results, status, err := hi.CheckIntegrity(); err != nil {
				tx.Rollback()
				handleIntegrityError(w, results, status, err)
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

// GetParamOrDefault returns a URL query parameter value or a default value if it is not present or empty.
func GetParamOrDefault(r *http.Request, name, defaultValue string) string {
	out := GetParam(r, name)
	if out == "" {
		return defaultValue
	}
	return out
}

func HandleError(num int, err error, w http.ResponseWriter) {
	AddCorsHeaders(w)
	w.WriteHeader(num)
	msg := fmt.Sprintf("%d request error: %v\n", num, err)
	w.Write([]byte(msg))
	log.Printf(msg)
}

func handleIntegrityError(w http.ResponseWriter, results proto.Message, status int, err error) {
	AddCorsHeaders(w)
	w.WriteHeader(status)
	if results != nil {
		SendResponse(results, w)
	} else {
		msg := fmt.Sprintf("%d request error: %v\n", http.StatusFailedDependency, err)
		w.Write([]byte(msg))
	}
}

func AddCorsHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Origin, Accept, Authorization")
	w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
}

func GetRequest(pb proto.Message, r *http.Request) error {
	if err := jsonpb.Unmarshal(r.Body, pb); err != nil && err != io.EOF {
		return err
	}
	return nil
}

func SendResponse(resp proto.Message, w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	AddCorsHeaders(w)
	ma := jsonpb.Marshaler{}
	return ma.Marshal(w, resp)
}

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
