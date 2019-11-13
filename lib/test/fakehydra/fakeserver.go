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
	"google3/third_party/golang/klog/glog/glog"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/apis/hydraapi"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common"
)

// Server is fake hydra server.
type Server struct {
	GetLoginRequestReq       string
	GetLoginRequestErr       *hydraapi.GenericError
	GetLoginRequestResp      *hydraapi.LoginRequest
	AcceptLoginRequestReq    *hydraapi.HandledLoginRequest
	AcceptLoginRequestErr    *hydraapi.GenericError
	AcceptLoginRequestResp   *hydraapi.RequestHandlerResponse
	RejectLoginRequestReq    *hydraapi.RequestDeniedError
	RejectLoginRequestErr    *hydraapi.GenericError
	RejectLoginRequestResp   *hydraapi.RequestHandlerResponse
	GetConsentRequestReq     string
	GetConsentRequestErr     *hydraapi.GenericError
	GetConsentRequestResp    *hydraapi.ConsentRequest
	AcceptConsentRequestReq  *hydraapi.HandledConsentRequest
	AcceptConsentRequestErr  *hydraapi.GenericError
	AcceptConsentRequestResp *hydraapi.RequestHandlerResponse
	RejectConsentRequestReq  *hydraapi.RequestDeniedError
	RejectConsentRequestErr  *hydraapi.GenericError
	RejectConsentRequestResp *hydraapi.RequestHandlerResponse
}

// New creates fake hydra server.
func New(r *mux.Router) *Server {
	s := &Server{}

	r.HandleFunc("/oauth2/auth/requests/login", s.getLoginRequest)
	r.HandleFunc("/oauth2/auth/requests/login/accept", s.acceptLoginRequest)
	r.HandleFunc("/oauth2/auth/requests/login/reject", s.rejectLoginRequest)
	r.HandleFunc("/oauth2/auth/requests/consent", s.getConsentRequest)
	r.HandleFunc("/oauth2/auth/requests/consent/accept", s.acceptConsentRequest)
	r.HandleFunc("/oauth2/auth/requests/consent/reject", s.rejectConsentRequest)

	return s
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

func (s *Server) acceptLoginRequest(w http.ResponseWriter, r *http.Request) {
	s.AcceptLoginRequestReq = &hydraapi.HandledLoginRequest{}
	common.DecodeJSONFromBody(r.Body, s.AcceptLoginRequestReq)
	s.write(w, s.AcceptLoginRequestErr, s.AcceptLoginRequestResp)
}

func (s *Server) rejectLoginRequest(w http.ResponseWriter, r *http.Request) {
	s.RejectLoginRequestReq = &hydraapi.RequestDeniedError{}
	common.DecodeJSONFromBody(r.Body, s.RejectLoginRequestReq)
	s.write(w, s.RejectLoginRequestErr, s.RejectLoginRequestResp)
}

func (s *Server) getConsentRequest(w http.ResponseWriter, r *http.Request) {
	s.GetConsentRequestReq = r.URL.Query().Get("consent_challenge")
	s.write(w, s.GetConsentRequestErr, s.GetConsentRequestResp)
}

func (s *Server) acceptConsentRequest(w http.ResponseWriter, r *http.Request) {
	s.AcceptConsentRequestReq = &hydraapi.HandledConsentRequest{}
	common.DecodeJSONFromBody(r.Body, s.AcceptConsentRequestReq)
	s.write(w, s.AcceptConsentRequestErr, s.AcceptConsentRequestResp)
}

func (s *Server) rejectConsentRequest(w http.ResponseWriter, r *http.Request) {
	s.RejectConsentRequestReq = &hydraapi.RequestDeniedError{}
	common.DecodeJSONFromBody(r.Body, s.RejectConsentRequestReq)
	s.write(w, s.RejectConsentRequestErr, s.RejectConsentRequestResp)
}
