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

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"github.com/google/go-cmp/cmp/cmpopts" /* copybara-comment */
	"github.com/gorilla/mux" /* copybara-comment */
	"github.com/go-openapi/strfmt" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/apis/hydraapi" /* copybara-comment: hydraapi */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakehydra" /* copybara-comment: fakehydra */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/httptestclient" /* copybara-comment: httptestclient */
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
	s := fakehydra.New(r)
	c := httptestclient.New(r)
	return s, c
}

func TestGetLoginRequest(t *testing.T) {
	s, c := setup()

	s.GetLoginRequestResp = &hydraapi.LoginRequest{Challenge: challenge}
	resp, err := GetLoginRequest(c, hydraAdminURL, challenge)
	if err != nil {
		t.Errorf("GetLoginRequest return error: %v", err)
	}

	if s.GetLoginRequestReq != challenge {
		t.Errorf("challenge want %s got %s", challenge, s.GetLoginRequestReq)
	}

	if resp.Challenge != challenge {
		t.Errorf("resp.Challenge want %s got %s", challenge, resp.Challenge)
	}
}

func TestGetLoginRequest_Error(t *testing.T) {
	s, c := setup()
	s.GetLoginRequestResp = &hydraapi.LoginRequest{Challenge: challenge}
	s.GetLoginRequestErr = genericError
	if _, err := GetLoginRequest(c, hydraAdminURL, challenge); err == nil {
		t.Errorf("GetLoginRequest wants error")
	}
}

func TestAcceptLogin(t *testing.T) {
	s, c := setup()
	req := &hydraapi.HandledLoginRequest{Subject: &subject}

	s.AcceptLoginResp = &hydraapi.RequestHandlerResponse{RedirectTo: callbackURL}
	resp, err := AcceptLogin(c, hydraAdminURL, challenge, req)
	if err != nil {
		t.Errorf("AcceptLogin return error: %v", err)
	}

	if *s.AcceptLoginReq.Subject != subject {
		t.Errorf("subject want %s got %s", subject, *s.AcceptLoginReq.Subject)
	}

	if resp.RedirectTo != callbackURL {
		t.Errorf("resp.RedirectTo want %s got %s", callbackURL, resp.RedirectTo)
	}
}

func TestAcceptLogin_Error(t *testing.T) {
	s, c := setup()
	req := &hydraapi.HandledLoginRequest{Subject: &subject}
	s.AcceptLoginResp = &hydraapi.RequestHandlerResponse{RedirectTo: callbackURL}
	s.AcceptLoginErr = genericError

	if _, err := AcceptLogin(c, hydraAdminURL, challenge, req); err == nil {
		t.Errorf("AcceptLogin wants error")
	}
}

func TestRejectLogin(t *testing.T) {
	s, c := setup()
	req := &hydraapi.RequestDeniedError{Code: rejectCode}

	s.RejectLoginResp = &hydraapi.RequestHandlerResponse{RedirectTo: callbackURL}
	resp, err := RejectLogin(c, hydraAdminURL, challenge, req)
	if err != nil {
		t.Errorf("RejectLogin return error: %v", err)
	}

	if s.RejectLoginReq.Code != rejectCode {
		t.Errorf("rejectCode want %d got %d", rejectCode, s.RejectLoginReq.Code)
	}

	if resp.RedirectTo != callbackURL {
		t.Errorf("resp.RedirectTo want %s got %s", callbackURL, resp.RedirectTo)
	}
}

func TestRejectLogin_Error(t *testing.T) {
	s, c := setup()
	req := &hydraapi.RequestDeniedError{Code: rejectCode}
	s.RejectLoginResp = &hydraapi.RequestHandlerResponse{RedirectTo: callbackURL}
	s.RejectLoginErr = genericError

	if _, err := RejectLogin(c, hydraAdminURL, challenge, req); err == nil {
		t.Errorf("RejectLogin wants error")
	}
}

func TestGetConsentRequest(t *testing.T) {
	s, c := setup()

	s.GetConsentRequestResp = &hydraapi.ConsentRequest{Challenge: challenge}
	resp, err := GetConsentRequest(c, hydraAdminURL, challenge)
	if err != nil {
		t.Errorf("GetConsentRequest return error: %v", err)
	}

	if s.GetConsentRequestReq != challenge {
		t.Errorf("challenge want %s got %s", challenge, s.GetConsentRequestReq)
	}

	if resp.Challenge != challenge {
		t.Errorf("resp.Challenge want %s got %s", challenge, resp.Challenge)
	}
}

func TestGetConsentRequest_Error(t *testing.T) {
	s, c := setup()
	s.GetConsentRequestResp = &hydraapi.ConsentRequest{Challenge: challenge}
	s.GetConsentRequestErr = genericError

	if _, err := GetConsentRequest(c, hydraAdminURL, challenge); err == nil {
		t.Errorf("GetConsentRequest wants error")
	}
}

func TestAcceptConsent(t *testing.T) {
	s, c := setup()
	req := &hydraapi.HandledConsentRequest{Remember: true}

	s.AcceptConsentResp = &hydraapi.RequestHandlerResponse{RedirectTo: callbackURL}
	resp, err := AcceptConsent(c, hydraAdminURL, challenge, req)
	if err != nil {
		t.Errorf("AcceptConsent return error: %v", err)
	}

	if !s.AcceptConsentReq.Remember {
		t.Errorf("Remember want true got false")
	}

	if resp.RedirectTo != callbackURL {
		t.Errorf("resp.RedirectTo want %s got %s", callbackURL, resp.RedirectTo)
	}
}

func TestAcceptConsent_Error(t *testing.T) {
	s, c := setup()
	req := &hydraapi.HandledConsentRequest{Remember: true}
	s.AcceptConsentResp = &hydraapi.RequestHandlerResponse{RedirectTo: callbackURL}
	s.AcceptConsentErr = genericError

	if _, err := AcceptConsent(c, hydraAdminURL, challenge, req); err == nil {
		t.Errorf("AcceptConsent wants error")
	}
}

func TestRejectConsent(t *testing.T) {
	s, c := setup()
	req := &hydraapi.RequestDeniedError{Code: rejectCode}

	s.RejectConsentResp = &hydraapi.RequestHandlerResponse{RedirectTo: callbackURL}
	resp, err := RejectConsent(c, hydraAdminURL, challenge, req)
	if err != nil {
		t.Errorf("RejectConsent return error: %v", err)
	}

	if s.RejectConsentReq.Code != rejectCode {
		t.Errorf("rejectCode want %d got %d", rejectCode, s.RejectConsentReq.Code)
	}

	if resp.RedirectTo != callbackURL {
		t.Errorf("resp.RedirectTo want %s got %s", callbackURL, resp.RedirectTo)
	}
}

func TestRejectConsent_Error(t *testing.T) {
	s, c := setup()
	req := &hydraapi.RequestDeniedError{Code: rejectCode}
	s.RejectConsentResp = &hydraapi.RequestHandlerResponse{RedirectTo: callbackURL}
	s.RejectConsentErr = genericError

	if _, err := RejectConsent(c, hydraAdminURL, challenge, req); err == nil {
		t.Errorf("RejectConsent wants error")
	}
}

func TestListClients(t *testing.T) {
	s, c := setup()

	s.ListClientsResp = []*hydraapi.Client{
		{ClientID: "c1"},
		{ClientID: "c2"},
	}

	resp, err := ListClients(c, hydraAdminURL)
	if err != nil {
		t.Errorf("ListClients return error: %v", err)
	}

	if diff := cmp.Diff(s.ListClientsResp, resp, cmpopts.IgnoreUnexported(strfmt.DateTime{})); len(diff) > 0 {
		t.Errorf("ListClients returns diff (-want, +got): %s", diff)
	}
}

func TestListClients_Error(t *testing.T) {
	s, c := setup()

	s.ListClientsResp = []*hydraapi.Client{
		{ClientID: "c1"},
		{ClientID: "c2"},
	}
	s.ListClientsErr = genericError
	if _, err := ListClients(c, hydraAdminURL); err == nil {
		t.Errorf("ListClients wants error")
	}
}

func TestCreateClient(t *testing.T) {
	s, c := setup()

	clientID := "c1"

	s.CreateClientResp = &hydraapi.Client{
		ClientID: clientID,
		Secret:   "s",
	}

	req := &hydraapi.Client{ClientID: clientID}

	resp, err := CreateClient(c, hydraAdminURL, req)
	if err != nil {
		t.Errorf("CreateClient return error: %v", err)
	}

	if diff := cmp.Diff(req, s.CreateClientReq, cmpopts.IgnoreUnexported(strfmt.DateTime{})); len(diff) > 0 {
		t.Errorf("CreateClient request unexpected, (-want, +got): %s", diff)
	}

	if diff := cmp.Diff(s.CreateClientResp, resp, cmpopts.IgnoreUnexported(strfmt.DateTime{})); len(diff) > 0 {
		t.Errorf("CreateClient returns diff (-want, +got): %s", diff)
	}
}

func TestCreateClient_Error(t *testing.T) {
	s, c := setup()

	clientID := "c1"

	req := &hydraapi.Client{ClientID: clientID}
	s.CreateClientResp = &hydraapi.Client{
		ClientID: clientID,
		Secret:   "s",
	}
	s.CreateClientErr = genericError
	if _, err := CreateClient(c, hydraAdminURL, req); err == nil {
		t.Errorf("CreateClient wants error")
	}
}

func TestGetClient(t *testing.T) {
	s, c := setup()

	clientID := "c1"

	s.GetClientResp = &hydraapi.Client{ClientID: clientID}

	resp, err := GetClient(c, hydraAdminURL, clientID)
	if err != nil {
		t.Errorf("GetClient return error: %v", err)
	}

	if s.GetClientID != clientID {
		t.Errorf("GetClientID = %s, wants %s", s.GetClientID, clientID)
	}

	if diff := cmp.Diff(s.GetClientResp, resp, cmpopts.IgnoreUnexported(strfmt.DateTime{})); len(diff) > 0 {
		t.Errorf("GetClient returns diff (-want, +got): %s", diff)
	}
}

func TestGetClient_Error(t *testing.T) {
	s, c := setup()

	clientID := "c1"

	s.GetClientResp = &hydraapi.Client{ClientID: clientID}
	s.GetClientErr = genericError

	if _, err := GetClient(c, hydraAdminURL, clientID); err == nil {
		t.Errorf("GetClient wants error")
	}
}

func TestUpdateClient(t *testing.T) {
	s, c := setup()

	clientID := "c1"

	req := &hydraapi.Client{ClientID: clientID}

	s.UpdateClientResp = &hydraapi.Client{
		ClientID: clientID,
		Secret:   "s",
	}

	resp, err := UpdateClient(c, hydraAdminURL, clientID, req)
	if err != nil {
		t.Errorf("UpdateClient return error: %v", err)
	}

	if s.UpdateClientID != clientID {
		t.Errorf("UpdateClientID = %s, wants %s", s.UpdateClientID, clientID)
	}

	if diff := cmp.Diff(req, s.UpdateClientReq, cmpopts.IgnoreUnexported(strfmt.DateTime{})); len(diff) > 0 {
		t.Errorf("UpdateClient request unexpected, (-want, +got): %s", diff)
	}

	if diff := cmp.Diff(s.UpdateClientResp, resp, cmpopts.IgnoreUnexported(strfmt.DateTime{})); len(diff) > 0 {
		t.Errorf("UpdateClient returns diff (-want, +got): %s", diff)
	}
}

func TestUpdateClient_Error(t *testing.T) {
	s, c := setup()

	clientID := "c1"

	req := &hydraapi.Client{ClientID: clientID}

	s.UpdateClientResp = &hydraapi.Client{
		ClientID: clientID,
		Secret:   "s",
	}
	s.UpdateClientErr = genericError
	if _, err := UpdateClient(c, hydraAdminURL, clientID, req); err == nil {
		t.Errorf("UpdateClient wants error")
	}
}

func TestDeleteClient(t *testing.T) {
	s, c := setup()

	clientID := "c1"

	err := DeleteClient(c, hydraAdminURL, clientID)
	if err != nil {
		t.Errorf("DeleteClient return error: %v", err)
	}

	if s.DeleteClientID != clientID {
		t.Errorf("DeleteClientID = %s, wants %s", s.DeleteClientID, clientID)
	}
}

func TestDeleteClient_Error(t *testing.T) {
	s, c := setup()

	clientID := "c1"
	s.DeleteClientErr = genericError
	if err := DeleteClient(c, hydraAdminURL, clientID); err == nil {
		t.Errorf("DeleteClient wants error")
	}
}

func TestIntrospect(t *testing.T) {
	s, c := setup()

	tok := "tok"
	s.IntrospectionResp = &hydraapi.Introspection{ClientID: "cid"}

	i, err := Introspect(c, hydraAdminURL, tok)
	if err != nil {
		t.Errorf("Introspect return error: %v", err)
	}

	if s.IntrospectionReqToken != tok {
		t.Errorf("s.IntrospectionReqToken = %s, wants %s", s.IntrospectionReqToken, tok)
	}

	if i.ClientID != s.IntrospectionResp.ClientID {
		t.Errorf("i.ClientID = %s, wants %s", i.ClientID, s.IntrospectionResp.ClientID)
	}
}

func TestIntrospect_Error(t *testing.T) {
	s, c := setup()

	tok := "tok"
	s.IntrospectionErr = genericError

	if _, err := Introspect(c, hydraAdminURL, tok); err == nil {
		t.Errorf("Introspect wants error: %v", err)
	}
}
