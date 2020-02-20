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

// Package handlerfactory allows creating HTTP handlers for services.
package handlerfactory

import (
	"fmt"
	"net/http"
	"regexp"

	"github.com/gorilla/mux" /* copybara-comment */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
)

// extractVars extracts variables from a request.
// defined here to faciliated testing.
// TODO: do not rely on registeration of routes at global mux for parsing names,
// pass it explicitly.
var extractVars = mux.Vars

// HandlerFactory contains the information about a handler service.
// Essentially the service interface + some options to the HTTP wrapper for it.
type HandlerFactory struct {
	TypeName            string
	NameField           string
	PathPrefix          string
	HasNamedIdentifiers bool
	NameChecker         map[string]*regexp.Regexp
	NewHandler          func(w http.ResponseWriter, r *http.Request) HandlerInterface
}

// HandlerInterface is the role interface for a service that will be wrapped.
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

// MakeHandler created a HTTP handler wrapper around a given service.
func MakeHandler(s storage.Store, hri *HandlerFactory) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// TODO: get rid of NewHandler and directly depend on service.
		// Pass w and r explicitly to the service methods.
		hi := hri.NewHandler(w, r)
		var op func(string) error
		switch r.Method {
		case http.MethodGet:
			op = hi.Get
		case http.MethodPost:
			op = hi.Post
		case http.MethodPut:
			op = hi.Put
		case http.MethodPatch:
			op = hi.Patch
		case http.MethodDelete:
			op = hi.Remove
		default:
			httputil.WriteStatusError(w, status.Errorf(codes.InvalidArgument, "request method not supported: %q", r.Method))
			return
		}

		// TODO: move inside each service and don't pass NameChecker here.
		name, vars, err := ValidateResourceName(r, hri.NameField, hri.NameChecker)
		if err != nil {
			httputil.WriteError(w, http.StatusBadRequest, err)
		}
		typ := hri.TypeName
		desc := r.Method + " " + typ

		tx, err := s.Tx(r.Method != http.MethodGet)
		if err != nil {
			httputil.WriteError(w, http.StatusServiceUnavailable, fmt.Errorf("service dependencies not available; try again later"))
			return
		}
		defer tx.Finish()

		// Get rid of Setup and move creation of transaction inside service methods.
		//
		if _, err = hi.Setup(tx); err != nil {
			httputil.WriteStatusError(w, err)
			return
		}

		// TODO: Replace NormalizeInput with a ParseReq that returns a request proto message.
		// TODO: Explicitly pass the message to the service methods.
		if err := hi.NormalizeInput(name, vars); err != nil {
			httputil.WriteStatusError(w, status.Errorf(codes.InvalidArgument, "%v", err))
			return
		}

		// TODO: get rid of LookupItem and move this inside the service methods.
		exists := hi.LookupItem(name, vars)
		switch r.Method {
		case http.MethodPost:
			if exists {
				httputil.WriteError(w, http.StatusConflict, fmt.Errorf("%s already exists: %q", typ, name))
				return
			}
		case http.MethodGet, http.MethodPatch, http.MethodPut, http.MethodDelete:
			if !exists {
				if hri.HasNamedIdentifiers {
					httputil.WriteStatusError(w, status.Errorf(codes.NotFound, "%s not found: %q", typ, name))
					return
				}
				httputil.WriteStatusError(w, status.Errorf(codes.NotFound, "%s not found", typ))
				return
			}
		}

		if r.Method == http.MethodGet {
			if err := op(name); err != nil {
				httputil.WriteError(w, http.StatusBadRequest, err)
				return
			}
			return
		}
		if err := RunRMWTx(tx, op, hi.CheckIntegrity, hi.Save, name, vars, typ, desc); err != nil {
			httputil.WriteStatusError(w, err)
			return
		}
	}
}

// ValidateResourceName checks if the resource name is valid.
// Returns the resource name and vars in it.
func ValidateResourceName(r *http.Request, field string, nameRE map[string]*regexp.Regexp) (string, map[string]string, error) {
	nameVar := "name"
	if len(field) > 0 {
		nameVar = field
	}
	vars := extractVars(r)
	name := vars[nameVar]

	for k, v := range vars {
		if err := httputil.CheckName(k, v, nameRE); err != nil {
			return "", nil, err
		}
	}
	return name, vars, nil
}

// RunRMWTx performs a RMW operation.
// Saves the transaction after performing integraty check.
// Rolls back the transaction on any failure.
// TODO: move outside this package. Service handlers should call it.
func RunRMWTx(
	tx storage.Tx,
	op func(string) error,
	check func() *status.Status,
	save func(storage.Tx, string, map[string]string, string, string) error,
	name string,
	vars map[string]string,
	typ string,
	desc string,
) error {
	if err := op(name); err != nil {
		return status.Errorf(codes.InvalidArgument, "%v", err)
	}
	if st := check(); st != nil {
		tx.Rollback()
		return st.Err()
	}
	if err := save(tx, name, vars, desc, typ); err != nil {
		tx.Rollback()
		return status.Errorf(codes.Internal, "%v", err)
	}
	return nil
}
