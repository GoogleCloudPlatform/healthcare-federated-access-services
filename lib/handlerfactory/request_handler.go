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

package handlerfactory

import (
	"fmt"
	"net/http"
	"regexp"

	"github.com/gorilla/mux" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
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
		nameVar := "name"
		if len(hri.NameField) > 0 {
			nameVar = hri.NameField
		}
		name := vars[nameVar]

		for k, v := range vars {
			if err := httputil.CheckName(k, v, hri.NameChecker); err != nil {
				httputil.WriteError(w, http.StatusBadRequest, err)
				return
			}
		}
		tx, err := s.GetStore().Tx(r.Method != http.MethodGet)
		if err != nil {
			httputil.WriteError(w, http.StatusServiceUnavailable, fmt.Errorf("service dependencies not available; try again later"))
			return
		}
		defer tx.Finish()

		hi := hri.NewHandler(w, r)
		status, err := hi.Setup(tx)
		if err != nil {
			httputil.WriteError(w, status, err)
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
			httputil.WriteError(w, http.StatusNotFound, err)
			return
		}

		switch r.Method {
		case http.MethodGet:
			if err := hi.NormalizeInput(name, vars); err != nil {
				httputil.WriteError(w, http.StatusBadRequest, err)
				return
			}
			if err := hi.Get(name); err != nil {
				httputil.WriteError(w, http.StatusBadRequest, err)
				return
			}
		case http.MethodPost:
			if itemOk {
				httputil.WriteError(w, http.StatusConflict, fmt.Errorf("%s already exists: %q", typ, name))
				return
			}
			if err := hi.NormalizeInput(name, vars); err != nil {
				httputil.WriteError(w, http.StatusBadRequest, err)
				return
			}
			if err = hi.Post(name); err != nil {
				httputil.WriteError(w, http.StatusBadRequest, err)
				return
			}
			if stat := hi.CheckIntegrity(); stat != nil {
				tx.Rollback()
				handleIntegrityError(stat, w)
				return
			}
			if err := hi.Save(tx, name, vars, desc, typ); err != nil {
				tx.Rollback()
				httputil.WriteError(w, http.StatusInternalServerError, err)
				return
			}
		case http.MethodPut:
			fallthrough
		case http.MethodPatch:
			if err := hi.NormalizeInput(name, vars); err != nil {
				httputil.WriteError(w, http.StatusBadRequest, err)
				return
			}
			if r.Method == http.MethodPut {
				err = hi.Put(name)
			} else {
				err = hi.Patch(name)
			}
			if err != nil {
				tx.Rollback()
				httputil.WriteError(w, http.StatusBadRequest, err)
				return
			}
			if stat := hi.CheckIntegrity(); stat != nil {
				tx.Rollback()
				handleIntegrityError(stat, w)
				return
			}
			if err := hi.Save(tx, name, vars, desc, typ); err != nil {
				tx.Rollback()
				httputil.WriteError(w, http.StatusInternalServerError, err)
				return
			}
		case http.MethodDelete:
			if err := hi.Remove(name); err != nil {
				httputil.WriteError(w, http.StatusBadRequest, err)
				return
			}
			if stat := hi.CheckIntegrity(); stat != nil {
				tx.Rollback()
				handleIntegrityError(stat, w)
				return
			}
			if err := hi.Save(tx, name, vars, desc, typ); err != nil {
				tx.Rollback()
				httputil.WriteError(w, http.StatusInternalServerError, err)
				return
			}
		default:
			httputil.WriteError(w, http.StatusBadRequest, fmt.Errorf("request method not supported: %q", r.Method))
			return
		}
	}
}

func handleIntegrityError(stat *status.Status, w http.ResponseWriter) {
	if len(stat.Details()) > 0 {
		httputil.WriteStatus(w, stat)
		return
	}
	httputil.WriteError(w, httputil.HTTPStatus(stat.Code()), fmt.Errorf("%s", stat.Message()))
}
