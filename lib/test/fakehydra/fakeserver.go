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

// Package fakehydra contains fake hydra server for testing
package fakehydra

import (
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/gorilla/mux" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/apis/hydraapi" /* copybara-comment: hydraapi */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common" /* copybara-comment: common */

	glog "github.com/golang/glog" /* copybara-comment */
)

// Data stores data in fake hydra server. Make it easier to reset.
type Data struct {
	GetLoginRequestReq    string
	GetLoginRequestErr    *hydraapi.GenericError
	GetLoginRequestResp   *hydraapi.LoginRequest
	AcceptLoginReq        *hydraapi.HandledLoginRequest
	AcceptLoginErr        *hydraapi.GenericError
	AcceptLoginResp       *hydraapi.RequestHandlerResponse
	RejectLoginReq        *hydraapi.RequestDeniedError
	RejectLoginErr        *hydraapi.GenericError
	RejectLoginResp       *hydraapi.RequestHandlerResponse
	GetConsentRequestReq  string
	GetConsentRequestErr  *hydraapi.GenericError
	GetConsentRequestResp *hydraapi.ConsentRequest
	AcceptConsentReq      *hydraapi.HandledConsentRequest
	AcceptConsentErr      *hydraapi.GenericError
	AcceptConsentResp     *hydraapi.RequestHandlerResponse
	RejectConsentReq      *hydraapi.RequestDeniedError
	RejectConsentErr      *hydraapi.GenericError
	RejectConsentResp     *hydraapi.RequestHandlerResponse
	ListClientsErr        *hydraapi.GenericError
	ListClientsResp       []*hydraapi.Client
	CreateClientReq       *hydraapi.Client
	CreateClientErr       *hydraapi.GenericError
	CreateClientResp      *hydraapi.Client
	GetClientID           string
	GetClientErr          *hydraapi.GenericError
	GetClientResp         *hydraapi.Client
	UpdateClientID        string
	UpdateClientReq       *hydraapi.Client
	UpdateClientErr       *hydraapi.GenericError
	UpdateClientResp      *hydraapi.Client
	DeleteClientID        string
	DeleteClientErr       *hydraapi.GenericError
	IntrospectionReqToken string
	IntrospectionResp     *hydraapi.Introspection
	IntrospectionErr      *hydraapi.GenericError
}

// Server is fake hydra server.
type Server struct {
	Data
}

// New creates fake hydra server.
func New(r *mux.Router) *Server {
	s := &Server{Data{}}

	// These follow the methods used by the real Hydra.
	// See https://www.ory.sh/docs/hydra/sdk/api

	// oauth endpoints
	r.HandleFunc("/oauth2/auth/requests/login", s.getLoginRequest).Methods(http.MethodGet)
	r.HandleFunc("/oauth2/auth/requests/login/accept", s.acceptLogin).Methods(http.MethodPut)
	r.HandleFunc("/oauth2/auth/requests/login/reject", s.rejectLogin).Methods(http.MethodPut)
	r.HandleFunc("/oauth2/auth/requests/consent", s.getConsentRequest).Methods(http.MethodGet)
	r.HandleFunc("/oauth2/auth/requests/consent/accept", s.acceptConsent).Methods(http.MethodPut)
	r.HandleFunc("/oauth2/auth/requests/consent/reject", s.rejectConsent).Methods(http.MethodPut)
	r.HandleFunc("/oauth2/introspection", s.introspection).Methods(http.MethodPost)

	// client endpoints
	r.HandleFunc("/clients", s.listClients).Methods(http.MethodGet)
	r.HandleFunc("/clients", s.createClient).Methods(http.MethodPost)
	r.HandleFunc("/clients/{id}", s.getClient).Methods(http.MethodGet)
	r.HandleFunc("/clients/{id}", s.updateClient).Methods(http.MethodPut)
	r.HandleFunc("/clients/{id}", s.deleteClient).Methods(http.MethodDelete)

	return s
}

// Clear states in fake hydra server.
func (s *Server) Clear() {
	s.Data = Data{}
}

func (s *Server) write(w http.ResponseWriter, code int, e *hydraapi.GenericError, resp interface{}) {
	body := resp
	if e != nil {
		code = int(e.Code)
		body = e
	}

	if err := common.EncodeJSONToResponse(w, code, body); err != nil {
		glog.Errorf("common.EncodeJSONToResponse(w, %d, %v) failed %v", code, body, err)
		http.Error(w, "encoding the response failed", http.StatusInternalServerError)
	}
}

func (s *Server) getLoginRequest(w http.ResponseWriter, r *http.Request) {
	s.GetLoginRequestReq = r.URL.Query().Get("login_challenge")
	s.write(w, http.StatusOK, s.GetLoginRequestErr, s.GetLoginRequestResp)
}

func (s *Server) acceptLogin(w http.ResponseWriter, r *http.Request) {
	s.AcceptLoginReq = &hydraapi.HandledLoginRequest{}
	common.DecodeJSONFromBody(r.Body, s.AcceptLoginReq)
	s.write(w, http.StatusOK, s.AcceptLoginErr, s.AcceptLoginResp)
}

func (s *Server) rejectLogin(w http.ResponseWriter, r *http.Request) {
	s.RejectLoginReq = &hydraapi.RequestDeniedError{}
	common.DecodeJSONFromBody(r.Body, s.RejectLoginReq)
	s.write(w, http.StatusOK, s.RejectLoginErr, s.RejectLoginResp)
}

func (s *Server) getConsentRequest(w http.ResponseWriter, r *http.Request) {
	s.GetConsentRequestReq = r.URL.Query().Get("consent_challenge")
	s.write(w, http.StatusOK, s.GetConsentRequestErr, s.GetConsentRequestResp)
}

func (s *Server) acceptConsent(w http.ResponseWriter, r *http.Request) {
	s.AcceptConsentReq = &hydraapi.HandledConsentRequest{}
	common.DecodeJSONFromBody(r.Body, s.AcceptConsentReq)
	s.write(w, http.StatusOK, s.AcceptConsentErr, s.AcceptConsentResp)
}

func (s *Server) rejectConsent(w http.ResponseWriter, r *http.Request) {
	s.RejectConsentReq = &hydraapi.RequestDeniedError{}
	common.DecodeJSONFromBody(r.Body, s.RejectConsentReq)
	s.write(w, http.StatusOK, s.RejectConsentErr, s.RejectConsentResp)
}

func (s *Server) introspection(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		glog.Infof("ioutil.ReadAll() failed: %s", err)
	}

	q, _ := url.ParseQuery(string(b))
	if err != nil {
		glog.Infof("url.ParseQuery(%s) failed: %s", string(b), err)
	}

	s.IntrospectionReqToken = q.Get("token")

	s.write(w, http.StatusOK, s.IntrospectionErr, s.IntrospectionResp)
}

func (s *Server) listClients(w http.ResponseWriter, r *http.Request) {
	s.write(w, http.StatusOK, s.ListClientsErr, s.ListClientsResp)
}

func (s *Server) createClient(w http.ResponseWriter, r *http.Request) {
	s.CreateClientReq = &hydraapi.Client{}
	common.DecodeJSONFromBody(r.Body, s.CreateClientReq)
	s.write(w, http.StatusCreated, s.CreateClientErr, s.CreateClientResp)
}

func (s *Server) getClient(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	s.GetClientID = vars["id"]
	s.write(w, http.StatusOK, s.GetClientErr, s.GetClientResp)
}

func (s *Server) updateClient(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	s.UpdateClientID = vars["id"]
	s.UpdateClientReq = &hydraapi.Client{}
	common.DecodeJSONFromBody(r.Body, s.UpdateClientReq)
	s.write(w, http.StatusOK, s.UpdateClientErr, s.UpdateClientResp)
}

func (s *Server) deleteClient(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	s.DeleteClientID = vars["id"]
	if s.DeleteClientErr != nil {
		s.write(w, int(s.DeleteClientErr.Code), s.DeleteClientErr, nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
