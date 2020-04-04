// Copyright 2020 Google LLC.
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

package ic

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/apis/hydraapi" /* copybara-comment: hydraapi */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakehydra" /* copybara-comment: fakehydra */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/ic/v1" /* copybara-comment: go_proto */
)

func Test_toInformationReleasePageArgs(t *testing.T) {
	d := &ga4gh.VisaData{
		StdClaims: ga4gh.StdClaims{
			Issuer: "fake-passport-issuer",
		},
		Assertion: ga4gh.Assertion{
			By:     "by",
			Type:   "type",
			Value:  "value",
			Source: "source",
		},
	}
	v, err := ga4gh.NewVisaFromData(d, "", ga4gh.RS256, testkeys.Default.Private, testkeys.Default.ID)
	if err != nil {
		t.Fatalf("NewVisaFromData(_) failed: %v", err)
	}
	id := &ga4gh.Identity{
		Subject: "sub",
		Name:    "name-1",
		Email:   "a@example.com",
		Identities: map[string][]string{
			"a@example.org": nil,
		},
		VisaJWTs: []string{string(v.JWT())},
	}

	t.Run("default", func(t *testing.T) {
		got := toInformationReleasePageArgs(id, "state", "client", "openid offline ga4gh_passport_v1 profile identities account_admin")
		want := &informationReleasePageArgs{
			ApplicationName: "client",
			Scope:           "openid offline ga4gh_passport_v1 profile identities account_admin",
			AssetDir:        "/identity/static",
			ID:              "sub",
			Offline:         true,
			Information: map[string][]*informationItem{
				"Permission": []*informationItem{
					{
						Title: "account_admin",
						Value: "manage (modify) this account",
						ID:    "account_admin",
					},
				},
				"Profile": []*informationItem{
					{Title: "Name", Value: "name-1", ID: "profile.name"},
					{Title: "Email", Value: "a@example.com", ID: "profile.email"},
					{Title: "Identities", Value: "a@example.org", ID: "identities"},
				},
				"Visas": []*informationItem{
					{
						Title: "type@source",
						Value: "value",
						ID:    "eyJ0eXBlIjoidHlwZSIsInNvdXJjZSI6InNvdXJjZSIsImJ5IjoiYnkiLCJpc3MiOiJmYWtlLXBhc3Nwb3J0LWlzc3VlciJ9",
					},
				},
			},
			State: "state",
		}
		if d := cmp.Diff(want, got); len(d) != 0 {
			t.Errorf("toInformationReleasePageArgs (-want, +got): %s", d)
		}
	})

	t.Run("less scope", func(t *testing.T) {
		got := toInformationReleasePageArgs(id, "state", "client", "openid offline")
		want := &informationReleasePageArgs{
			ApplicationName: "client",
			Scope:           "openid offline",
			AssetDir:        "/identity/static",
			ID:              "sub",
			Offline:         true,
			Information:     map[string][]*informationItem{},
			State:           "state",
		}
		if d := cmp.Diff(want, got); len(d) != 0 {
			t.Errorf("toInformationReleasePageArgs (-want, +got): %s", d)
		}
	})

	t.Run("less info", func(t *testing.T) {
		id := &ga4gh.Identity{
			Subject: "sub",
		}
		got := toInformationReleasePageArgs(id, "state", "client", "openid offline ga4gh_passport_v1 profile identities")
		want := &informationReleasePageArgs{
			ApplicationName: "client",
			Scope:           "openid offline ga4gh_passport_v1 profile identities",
			AssetDir:        "/identity/static",
			ID:              "sub",
			Offline:         true,
			Information:     map[string][]*informationItem{},
			State:           "state",
		}
		if d := cmp.Diff(want, got); len(d) != 0 {
			t.Errorf("toInformationReleasePageArgs (-want, +got): %s", d)
		}
	})
}

func sendAcceptInformationRelease(s *Service, cfg *pb.IcConfig, h *fakehydra.Server, scope, stateID string) (*http.Response, error) {
	// Ensure auth token state exists before request.
	tokState := &cpb.LoginState{
		Realm:            storage.DefaultRealm,
		Scope:            scope,
		ConsentChallenge: consentChallenge,
		Subject:          LoginSubject,
	}

	err := s.store.Write(storage.LoginStateDatatype, storage.DefaultRealm, storage.DefaultUser, authTokenStateID, storage.LatestRev, tokState, nil)
	if err != nil {
		return nil, err
	}

	// Ensure identity exists before request.
	acct := &cpb.Account{
		Properties: &cpb.AccountProperties{Subject: LoginSubject},
		State:      "ACTIVE",
		ConnectedAccounts: []*cpb.ConnectedAccount{
			{
				Properties: &cpb.AccountProperties{
					Subject: "foo@bar.com",
				},
			},
		},
	}
	err = s.store.Write(storage.AccountDatatype, storage.DefaultRealm, storage.DefaultUser, LoginSubject, storage.LatestRev, acct, nil)
	if err != nil {
		return nil, err
	}

	// Clear fakehydra server and set reject response.
	h.Clear()
	h.AcceptConsentResp = &hydraapi.RequestHandlerResponse{RedirectTo: hydraURL}
	h.RejectConsentResp = &hydraapi.RequestHandlerResponse{RedirectTo: hydraURL}

	// Send Request.
	query := url.Values{}
	query.Set("state", stateID)
	u := "https://" + domain + acceptInformationReleasePath
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, u, bytes.NewBufferString(query.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.Handler.ServeHTTP(w, r)

	return w.Result(), nil
}

func sendRejectInformationRelease(s *Service, cfg *pb.IcConfig, h *fakehydra.Server, scope, stateID string) (*http.Response, error) {
	// Ensure auth token state exists before request.
	tokState := &cpb.LoginState{
		Realm:            storage.DefaultRealm,
		Scope:            scope,
		ConsentChallenge: consentChallenge,
		Subject:          LoginSubject,
	}

	err := s.store.Write(storage.LoginStateDatatype, storage.DefaultRealm, storage.DefaultUser, authTokenStateID, storage.LatestRev, tokState, nil)
	if err != nil {
		return nil, err
	}

	// Ensure identity exists before request.
	acct := &cpb.Account{
		Properties: &cpb.AccountProperties{Subject: LoginSubject},
		State:      "ACTIVE",
		ConnectedAccounts: []*cpb.ConnectedAccount{
			{
				Properties: &cpb.AccountProperties{
					Subject: "foo@bar.com",
				},
			},
		},
	}
	err = s.store.Write(storage.AccountDatatype, storage.DefaultRealm, storage.DefaultUser, LoginSubject, storage.LatestRev, acct, nil)
	if err != nil {
		return nil, err
	}

	// Clear fakehydra server and set reject response.
	h.Clear()
	h.AcceptConsentResp = &hydraapi.RequestHandlerResponse{RedirectTo: hydraURL}
	h.RejectConsentResp = &hydraapi.RequestHandlerResponse{RedirectTo: hydraURL}

	// Send Request.
	query := url.Values{}
	query.Set("state", stateID)
	u := "https://" + domain + rejectInformationReleasePath
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, u, bytes.NewBufferString(query.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	s.Handler.ServeHTTP(w, r)

	return w.Result(), nil
}

func TestAcceptInformationRelease_Hydra_Accept(t *testing.T) {
	s, cfg, _, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	const scope = "openid profile"

	resp, err := sendAcceptInformationRelease(s, cfg, h, scope, authTokenStateID)
	if err != nil {
		t.Fatalf("sendAcceptInformationRelease(s, cfg, h, %s, %s) failed: %v", scope, authTokenStateID, err)
	}

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("resp.StatusCode wants %d got %d", http.StatusSeeOther, resp.StatusCode)
	}

	if l := resp.Header.Get("Location"); l != hydraURL {
		t.Errorf("resp.Location wants %s got %s", hydraURL, l)
	}

	if h.RejectConsentReq != nil {
		t.Errorf("RejectConsentReq wants nil got %v", h.RejectConsentReq)
	}

	if diff := cmp.Diff(h.AcceptConsentReq.GrantedScope, strings.Split(scope, " ")); len(diff) != 0 {
		t.Errorf("AcceptConsentReq.GrantedScope wants %s got %v", scope, h.AcceptConsentReq.GrantedScope)
	}

	email, ok := h.AcceptConsentReq.Session.IDToken["email"].(string)
	if !ok {
		t.Fatalf("Email in id token in wrong type")
	}

	wantEmail := LoginSubject + "@" + domain
	if email != wantEmail {
		t.Errorf("Email in id token wants %s got %s", wantEmail, email)
	}

	atid, ok := h.AcceptConsentReq.Session.AccessToken["tid"].(string)
	if !ok {
		t.Fatalf("tid in access token in wrong type")
	}

	itid, ok := h.AcceptConsentReq.Session.IDToken["tid"].(string)
	if !ok {
		t.Fatalf("tid in id token in wrong type")
	}

	if itid != atid {
		t.Errorf("tid in id token and access token should be the same, %s, %s", itid, atid)
	}
}

func TestAcceptInformationRelease_Hydra_Accept_Scoped(t *testing.T) {
	s, cfg, _, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	const scope = "openid"

	resp, err := sendAcceptInformationRelease(s, cfg, h, scope, authTokenStateID)
	if err != nil {
		t.Fatalf("sendAcceptInformationRelease(s, cfg, h, %s, %s) failed: %v", scope, authTokenStateID, err)
	}

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("resp.StatusCode wants %d got %d", http.StatusSeeOther, resp.StatusCode)
	}

	if l := resp.Header.Get("Location"); l != hydraURL {
		t.Errorf("resp.Location wants %s got %s", hydraURL, l)
	}

	if h.RejectConsentReq != nil {
		t.Errorf("RejectConsentReq wants nil got %v", h.RejectConsentReq)
	}

	if diff := cmp.Diff(h.AcceptConsentReq.GrantedScope, strings.Split(scope, " ")); len(diff) != 0 {
		t.Errorf("AcceptConsentReq.GrantedScope wants %s got %v", scope, h.AcceptConsentReq.GrantedScope)
	}

	if _, ok := h.AcceptConsentReq.Session.IDToken["email"]; ok {
		t.Fatalf("Email in id token should not exists")
	}

	atid, ok := h.AcceptConsentReq.Session.AccessToken["tid"].(string)
	if !ok {
		t.Fatalf("tid in access token in wrong type")
	}

	itid, ok := h.AcceptConsentReq.Session.IDToken["tid"].(string)
	if !ok {
		t.Fatalf("tid in id token in wrong type")
	}

	if itid != atid {
		t.Errorf("tid in id token and access token should be the same, %s, %s", itid, atid)
	}
}

func TestAcceptInformationRelease_Hydra_Reject(t *testing.T) {
	s, cfg, _, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	const scope = "openid profile"

	resp, err := sendRejectInformationRelease(s, cfg, h, scope, authTokenStateID)
	if err != nil {
		t.Fatalf("sendRejectInformationRelease(s, cfg, h, %s, %s) failed: %v", scope, authTokenStateID, err)
	}

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("resp.StatusCode wants %d got %d", http.StatusSeeOther, resp.StatusCode)
	}

	if l := resp.Header.Get("Location"); l != hydraURL {
		t.Errorf("resp.Location wants %s got %s", hydraURL, l)
	}

	if h.AcceptConsentReq != nil {
		t.Errorf("AcceptConsentReq wants nil got %v", h.RejectConsentReq)
	}

	if h.RejectConsentReq == nil {
		t.Errorf("RejectConsentReq got nil")
	}
}

func TestAcceptInformationRelease_Hydra_Endpoint(t *testing.T) {
	s, cfg, _, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	const scope = "openid profile identities"

	resp, err := sendAcceptInformationRelease(s, cfg, h, scope, authTokenStateID)
	if err != nil {
		t.Fatalf("sendAcceptInformationRelease(s, cfg, h, %s, %s) failed: %v", scope, authTokenStateID, err)
	}

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("resp.StatusCode wants %d got %d", http.StatusSeeOther, resp.StatusCode)
	}

	if l := resp.Header.Get("Location"); l != hydraURL {
		t.Errorf("resp.Location wants %s got %s", hydraURL, l)
	}

	if h.RejectConsentReq != nil {
		t.Errorf("RejectConsentReq wants nil got %v", h.RejectConsentReq)
	}

	if diff := cmp.Diff(h.AcceptConsentReq.GrantedScope, strings.Split(scope, " ")); len(diff) != 0 {
		t.Errorf("AcceptConsentReq.GrantedScope wants %s got %v", scope, h.AcceptConsentReq.GrantedScope)
	}

	want := []interface{}{"foo@bar.com"}
	if diff := cmp.Diff(want, h.AcceptConsentReq.Session.AccessToken["identities"]); len(diff) != 0 {
		t.Errorf("AcceptConsentReq.GrantedScope (-wants, +got) %s", diff)
	}

	atid, ok := h.AcceptConsentReq.Session.AccessToken["tid"].(string)
	if !ok {
		t.Fatalf("tid in access token in wrong type")
	}

	itid, ok := h.AcceptConsentReq.Session.IDToken["tid"].(string)
	if !ok {
		t.Fatalf("tid in id token in wrong type")
	}

	if itid != atid {
		t.Errorf("tid in id token and access token should be the same, %s, %s", itid, atid)
	}
}

func TestAcceptInformationRelease_Hydra_InvalidState(t *testing.T) {
	s, cfg, _, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	const scope = "openid profile"

	resp, err := sendAcceptInformationRelease(s, cfg, h, scope, "invalid")
	if err != nil {
		t.Fatalf("sendAcceptInformationRelease(s, cfg, h, %s, 'invalid') failed: %v", scope, err)
	}

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("resp.StatusCode wants %d got %d", http.StatusInternalServerError, resp.StatusCode)
	}

	if h.AcceptConsentReq != nil {
		t.Errorf("AcceptConsentReq wants nil got %v", h.AcceptConsentReq)
	}

	if h.RejectConsentReq != nil {
		t.Errorf("RejectConsentReq wants nil got %v", h.RejectConsentReq)
	}
}
