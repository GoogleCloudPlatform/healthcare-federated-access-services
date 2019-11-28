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

package hydra

import (
	"net/http"
	"testing"

	"github.com/gorilla/mux"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/apis/hydraapi"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakehydra"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/httptestclient"
)

const (
	hydraAdminURL = "http://example.com"
	callbackURL   = "http://example.com/callback"
	challenge     = "c-1234"
	rejectCode    = 400
)

var (
	name         = "n"
	genericError = &hydraapi.GenericError{
		Code:        http.StatusServiceUnavailable,
		Name:        &name,
		Description: "d",
	}
	subject = "s-1234"
)

func setup() (*fakehydra.Server, *http.Client) {
	r := mux.NewRouter()
	serv := fakehydra.New(r)
	cli := httptestclient.New(r)
	return serv, cli
}

func TestGetLoginRequest(t *testing.T) {
	serv, cli := setup()

	serv.GetLoginRequestResp = &hydraapi.LoginRequest{Challenge: challenge}
	resp, err := GetLoginRequest(cli, hydraAdminURL, challenge)
	if err != nil {
		t.Errorf("GetLoginRequest return error: %v", err)
	}

	if serv.GetLoginRequestReq != challenge {
		t.Errorf("challenge want %s got %s", challenge, serv.GetLoginRequestReq)
	}

	if resp.Challenge != challenge {
		t.Errorf("resp.Challenge want %s got %s", challenge, resp.Challenge)
	}

	serv.GetLoginRequestErr = genericError
	if _, err = GetLoginRequest(cli, hydraAdminURL, challenge); err == nil {
		t.Errorf("GetLoginRequest wants error")
	}
}

func TestAcceptLogin(t *testing.T) {
	serv, cli := setup()
	req := &hydraapi.HandledLoginRequest{Subject: &subject}

	serv.AcceptLoginResp = &hydraapi.RequestHandlerResponse{RedirectTo: callbackURL}
	resp, err := AcceptLogin(cli, hydraAdminURL, challenge, req)
	if err != nil {
		t.Errorf("AcceptLogin return error: %v", err)
	}

	if *serv.AcceptLoginReq.Subject != subject {
		t.Errorf("subject want %s got %s", subject, *serv.AcceptLoginReq.Subject)
	}

	if resp.RedirectTo != callbackURL {
		t.Errorf("resp.RedirectTo want %s got %s", callbackURL, resp.RedirectTo)
	}

	serv.AcceptLoginErr = genericError
	if _, err = AcceptLogin(cli, hydraAdminURL, challenge, req); err == nil {
		t.Errorf("AcceptLogin wants error")
	}
}

func TestRejectLogin(t *testing.T) {
	serv, cli := setup()
	req := &hydraapi.RequestDeniedError{Code: rejectCode}

	serv.RejectLoginResp = &hydraapi.RequestHandlerResponse{RedirectTo: callbackURL}
	resp, err := RejectLogin(cli, hydraAdminURL, challenge, req)
	if err != nil {
		t.Errorf("RejectLogin return error: %v", err)
	}

	if serv.RejectLoginReq.Code != rejectCode {
		t.Errorf("rejectCode want %d got %d", rejectCode, serv.RejectLoginReq.Code)
	}

	if resp.RedirectTo != callbackURL {
		t.Errorf("resp.RedirectTo want %s got %s", callbackURL, resp.RedirectTo)
	}

	serv.RejectLoginErr = genericError
	if _, err = RejectLogin(cli, hydraAdminURL, challenge, req); err == nil {
		t.Errorf("RejectLogin wants error")
	}
}

func TestGetConsentRequest(t *testing.T) {
	serv, cli := setup()

	serv.GetConsentRequestResp = &hydraapi.ConsentRequest{Challenge: challenge}
	resp, err := GetConsentRequest(cli, hydraAdminURL, challenge)
	if err != nil {
		t.Errorf("GetConsentRequest return error: %v", err)
	}

	if serv.GetConsentRequestReq != challenge {
		t.Errorf("challenge want %s got %s", challenge, serv.GetConsentRequestReq)
	}

	if resp.Challenge != challenge {
		t.Errorf("resp.Challenge want %s got %s", challenge, resp.Challenge)
	}

	serv.GetConsentRequestErr = genericError
	if _, err = GetConsentRequest(cli, hydraAdminURL, challenge); err == nil {
		t.Errorf("GetConsentRequest wants error")
	}
}

func TestAcceptConsent(t *testing.T) {
	serv, cli := setup()
	req := &hydraapi.HandledConsentRequest{Remember: true}

	serv.AcceptConsentResp = &hydraapi.RequestHandlerResponse{RedirectTo: callbackURL}
	resp, err := AcceptConsent(cli, hydraAdminURL, challenge, req)
	if err != nil {
		t.Errorf("AcceptConsent return error: %v", err)
	}

	if !serv.AcceptConsentReq.Remember {
		t.Errorf("Remember want true got false")
	}

	if resp.RedirectTo != callbackURL {
		t.Errorf("resp.RedirectTo want %s got %s", callbackURL, resp.RedirectTo)
	}

	serv.AcceptConsentErr = genericError
	if _, err = AcceptConsent(cli, hydraAdminURL, challenge, req); err == nil {
		t.Errorf("AcceptConsent wants error")
	}
}

func TestRejectConsent(t *testing.T) {
	serv, cli := setup()
	req := &hydraapi.RequestDeniedError{Code: rejectCode}

	serv.RejectConsentResp = &hydraapi.RequestHandlerResponse{RedirectTo: callbackURL}
	resp, err := RejectConsent(cli, hydraAdminURL, challenge, req)
	if err != nil {
		t.Errorf("RejectConsent return error: %v", err)
	}

	if serv.RejectConsentReq.Code != rejectCode {
		t.Errorf("rejectCode want %d got %d", rejectCode, serv.RejectConsentReq.Code)
	}

	if resp.RedirectTo != callbackURL {
		t.Errorf("resp.RedirectTo want %s got %s", callbackURL, resp.RedirectTo)
	}

	serv.RejectConsentErr = genericError
	if _, err = RejectConsent(cli, hydraAdminURL, challenge, req); err == nil {
		t.Errorf("RejectConsent wants error")
	}
}
