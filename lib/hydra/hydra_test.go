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

func TestAcceptLoginRequest(t *testing.T) {
	serv, cli := setup()
	req := &hydraapi.HandledLoginRequest{Subject: &subject}

	serv.AcceptLoginRequestResp = &hydraapi.RequestHandlerResponse{RedirectTo: callbackURL}
	resp, err := AcceptLoginRequest(cli, hydraAdminURL, challenge, req)
	if err != nil {
		t.Errorf("AcceptLoginRequest return error: %v", err)
	}

	if *serv.AcceptLoginRequestReq.Subject != subject {
		t.Errorf("subject want %s got %s", subject, *serv.AcceptLoginRequestReq.Subject)
	}

	if resp.RedirectTo != callbackURL {
		t.Errorf("resp.RedirectTo want %s got %s", callbackURL, resp.RedirectTo)
	}

	serv.AcceptLoginRequestErr = genericError
	if _, err = AcceptLoginRequest(cli, hydraAdminURL, challenge, req); err == nil {
		t.Errorf("AcceptLoginRequest wants error")
	}
}

func TestRejectLoginRequest(t *testing.T) {
	serv, cli := setup()
	req := &hydraapi.RequestDeniedError{Code: rejectCode}

	serv.RejectLoginRequestResp = &hydraapi.RequestHandlerResponse{RedirectTo: callbackURL}
	resp, err := RejectLoginRequest(cli, hydraAdminURL, challenge, req)
	if err != nil {
		t.Errorf("RejectLoginRequest return error: %v", err)
	}

	if serv.RejectLoginRequestReq.Code != rejectCode {
		t.Errorf("rejectCode want %d got %d", rejectCode, serv.RejectLoginRequestReq.Code)
	}

	if resp.RedirectTo != callbackURL {
		t.Errorf("resp.RedirectTo want %s got %s", callbackURL, resp.RedirectTo)
	}

	serv.RejectLoginRequestErr = genericError
	if _, err = RejectLoginRequest(cli, hydraAdminURL, challenge, req); err == nil {
		t.Errorf("RejectLoginRequest wants error")
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

func TestAcceptConsentRequest(t *testing.T) {
	serv, cli := setup()
	req := &hydraapi.HandledConsentRequest{Remember: true}

	serv.AcceptConsentRequestResp = &hydraapi.RequestHandlerResponse{RedirectTo: callbackURL}
	resp, err := AcceptConsentRequest(cli, hydraAdminURL, challenge, req)
	if err != nil {
		t.Errorf("AcceptConsentRequest return error: %v", err)
	}

	if !serv.AcceptConsentRequestReq.Remember {
		t.Errorf("Remember want true got false")
	}

	if resp.RedirectTo != callbackURL {
		t.Errorf("resp.RedirectTo want %s got %s", callbackURL, resp.RedirectTo)
	}

	serv.AcceptConsentRequestErr = genericError
	if _, err = AcceptConsentRequest(cli, hydraAdminURL, challenge, req); err == nil {
		t.Errorf("AcceptConsentRequest wants error")
	}
}

func TestRejectConsentRequest(t *testing.T) {
	serv, cli := setup()
	req := &hydraapi.RequestDeniedError{Code: rejectCode}

	serv.RejectConsentRequestResp = &hydraapi.RequestHandlerResponse{RedirectTo: callbackURL}
	resp, err := RejectConsentRequest(cli, hydraAdminURL, challenge, req)
	if err != nil {
		t.Errorf("RejectConsentRequest return error: %v", err)
	}

	if serv.RejectConsentRequestReq.Code != rejectCode {
		t.Errorf("rejectCode want %d got %d", rejectCode, serv.RejectConsentRequestReq.Code)
	}

	if resp.RedirectTo != callbackURL {
		t.Errorf("resp.RedirectTo want %s got %s", callbackURL, resp.RedirectTo)
	}

	serv.RejectConsentRequestErr = genericError
	if _, err = RejectConsentRequest(cli, hydraAdminURL, challenge, req); err == nil {
		t.Errorf("RejectConsentRequest wants error")
	}
}
