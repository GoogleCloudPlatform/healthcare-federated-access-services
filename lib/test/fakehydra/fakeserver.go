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
	"net/http"

	"github.com/gorilla/mux"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/apis/hydraapi"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common"

	glog "github.com/golang/glog"
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
}

// Server is fake hydra server.
type Server struct {
	Data
}

// New creates fake hydra server.
func New(r *mux.Router) *Server {
	s := &Server{Data{}}

	r.HandleFunc("/oauth2/auth/requests/login", s.getLoginRequest)
	r.HandleFunc("/oauth2/auth/requests/login/accept", s.acceptLogin)
	r.HandleFunc("/oauth2/auth/requests/login/reject", s.rejectLogin)
	r.HandleFunc("/oauth2/auth/requests/consent", s.getConsentRequest)
	r.HandleFunc("/oauth2/auth/requests/consent/accept", s.acceptConsent)
	r.HandleFunc("/oauth2/auth/requests/consent/reject", s.rejectConsent)

	return s
}

// Clear states in fake hydra server.
func (s *Server) Clear() {
	s.Data = Data{}
}

func (s *Server) write(w http.ResponseWriter, e *hydraapi.GenericError, resp interface{}) {
	code := http.StatusOK
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
	s.write(w, s.GetLoginRequestErr, s.GetLoginRequestResp)
}

func (s *Server) acceptLogin(w http.ResponseWriter, r *http.Request) {
	s.AcceptLoginReq = &hydraapi.HandledLoginRequest{}
	common.DecodeJSONFromBody(r.Body, s.AcceptLoginReq)
	s.write(w, s.AcceptLoginErr, s.AcceptLoginResp)
}

func (s *Server) rejectLogin(w http.ResponseWriter, r *http.Request) {
	s.RejectLoginReq = &hydraapi.RequestDeniedError{}
	common.DecodeJSONFromBody(r.Body, s.RejectLoginReq)
	s.write(w, s.RejectLoginErr, s.RejectLoginResp)
}

func (s *Server) getConsentRequest(w http.ResponseWriter, r *http.Request) {
	s.GetConsentRequestReq = r.URL.Query().Get("consent_challenge")
	s.write(w, s.GetConsentRequestErr, s.GetConsentRequestResp)
}

func (s *Server) acceptConsent(w http.ResponseWriter, r *http.Request) {
	s.AcceptConsentReq = &hydraapi.HandledConsentRequest{}
	common.DecodeJSONFromBody(r.Body, s.AcceptConsentReq)
	s.write(w, s.AcceptConsentErr, s.AcceptConsentResp)
}

func (s *Server) rejectConsent(w http.ResponseWriter, r *http.Request) {
	s.RejectConsentReq = &hydraapi.RequestDeniedError{}
	common.DecodeJSONFromBody(r.Body, s.RejectConsentReq)
	s.write(w, s.RejectConsentErr, s.RejectConsentResp)
}
