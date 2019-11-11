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

package ic

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	glog "github.com/golang/glog"
	"github.com/golang/protobuf/jsonpb"
	"github.com/google/go-cmp/cmp"
	"github.com/coreos/go-oidc"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/kms/fakeencryption"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakeoidcissuer"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/httptestclient"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys"
	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1"
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/ic/v1"
)

const (
	domain           = "example.com"
	hydraAdminURL    = "https://example.com"
	oidcIssuer       = "https://" + domain + "/oidc"
	testClientID     = "00000000-0000-0000-0000-000000000000"
	testClientSecret = "00000000-0000-0000-0000-000000000001"
)

func init() {
	err := os.Setenv("SERVICE_DOMAIN", domain)
	if err != nil {
		glog.Fatal("Setenv SERVICE_DOMAIN:", err)
	}
}

func TestOidcEndpoints(t *testing.T) {
	store := storage.NewMemoryStorage("ic-min", "testdata/config")
	s := NewService(context.Background(), domain, domain, hydraAdminURL, store, fakeencryption.New())
	cfg, err := s.loadConfig(nil, storage.DefaultRealm)
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}

	identity := &ga4gh.Identity{
		Subject: "sub",
	}
	tok, err := s.createToken(identity, "openid", oidcIssuer, "azp", storage.DefaultRealm, noNonce, time.Now(), time.Hour*1, cfg, nil)
	if err != nil {
		t.Fatalf("creating token: %v", err)
	}

	// Inject the mock http client to oidc client.
	client := httptestclient.New(s.Handler)
	ctx := oidc.ClientContext(context.Background(), client)
	provider, err := oidc.NewProvider(ctx, oidcIssuer)
	if err != nil {
		t.Fatal(err)
	}
	verifier := provider.Verifier(&oidc.Config{
		// TODO we should set correct "aud".
		ClientID: oidcIssuer,
	})

	_, err = verifier.Verify(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
}

func TestHandlers(t *testing.T) {
	store := storage.NewMemoryStorage("ic-min", "testdata/config")
	server, err := fakeoidcissuer.New(oidcIssuer, &testkeys.PersonaBrokerKey, "dam-min", "testdata/config")
	if err != nil {
		t.Fatalf("fakeoidcissuer.New(%q, _, _) failed: %v", oidcIssuer, err)
	}
	ctx := server.ContextWithClient(context.Background())
	crypt := fakeencryption.New()
	s := NewService(ctx, domain, domain, hydraAdminURL, store, crypt)
	cfg, err := s.loadConfig(nil, "test")
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}
	identity := &ga4gh.Identity{
		Issuer:  s.getIssuerString(),
		Subject: "someone-account",
	}
	refreshToken1 := createTestToken(t, s, identity, "openid refresh", cfg)
	refreshToken2 := createTestToken(t, s, identity, "openid refresh", cfg)
	tests := []test.HandlerTest{
		{
			Name:   "Get a self-owned token",
			Method: "GET",
			Path:   "/identity/v1alpha/test/token/dr_joe_elixir/123-456",
			Output: `{"tokenMetadata":{"tokenType":"refresh","issuedAt":"1560970669","scope":"ga4gh_passport_v1 identities profiles openid","identityProvider":"elixir"}}`,
			Status: http.StatusOK,
		},
		{
			Name:    "Get someone else's token as an admin",
			Method:  "GET",
			Path:    "/identity/v1alpha/test/token/someone-account/1a2-3b4",
			Persona: "admin",
			Output:  `{"tokenMetadata":{"tokenType":"refresh","issuedAt":"1560970669","scope":"ga4gh_passport_v1 openid","identityProvider":"google"}}`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get someone else's token as an non-admin",
			Method:  "GET",
			Path:    "/identity/v1alpha/test/token/dr_joe_elixir/1a2-3b4",
			Persona: "non-admin",
			Output:  `^.*token not found.*`,
			Status:  http.StatusNotFound,
		},
		{
			Name:   "Post a self-owned token",
			Method: "POST",
			Path:   "/identity/v1alpha/test/token/dr_joe_elixir/123-456",
			Output: `^.*exists`,
			Status: http.StatusConflict,
		},
		{
			Name:   "Put a self-owned token",
			Method: "PUT",
			Path:   "/identity/v1alpha/test/token/dr_joe_elixir/123-456",
			Output: `^.*not allowed`,
			Status: http.StatusBadRequest,
		},
		{
			Name:   "Patch a self-owned token",
			Method: "PATCH",
			Path:   "/identity/v1alpha/test/token/dr_joe_elixir/123-456",
			Output: `^.*not allowed`,
			Status: http.StatusBadRequest,
		},
		{
			Name:   "Delete a self-owned token",
			Method: "DELETE",
			Path:   "/identity/v1alpha/test/token/dr_joe_elixir/123-456",
			Output: "",
			Status: http.StatusOK,
		},
		{
			Name:   "Get a deleted token",
			Method: "GET",
			Path:   "/identity/v1alpha/test/token/dr_joe_elixir/123-456",
			Output: `^.*token not found.*`,
			Status: http.StatusNotFound,
		},
		{
			Name:   "Request an unsupported method at the /revoke endpoint",
			Method: "GET",
			Path:   "/identity/v1alpha/test/revoke",
			Input:  `token=6ImtpZCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJpY19lOWIxMDA2MDd`,
			IsForm: true,
			Output: `^.*method not supported.*`,
			Status: http.StatusBadRequest,
		},
		{
			Name:   "Delete a malformed token",
			Method: "POST",
			Path:   "/identity/v1alpha/test/revoke",
			Input:  `token=6ImtpZCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJpY19lOWIxMDA2MDd`,
			IsForm: true,
			Output: `^.*inspecting token.*`,
			Status: http.StatusUnauthorized,
		},
		{
			Name:    "Delete someone else's token as an admin",
			Method:  "POST",
			Path:    "/identity/v1alpha/test/revoke",
			Persona: "admin",
			Input:   "token=" + refreshToken1,
			IsForm:  true,
			Output:  "",
			Status:  http.StatusOK,
		},
		{
			Name:    "Delete someone else's token as a non-admin",
			Method:  "POST",
			Path:    "/identity/v1alpha/test/revoke",
			Input:   "token=" + refreshToken2,
			IsForm:  true,
			Persona: "non-admin",
			Output:  "",
			Status:  http.StatusOK,
		},
		{
			Name:    "Get linked accounts (foo)",
			Method:  "GET",
			Path:    "/identity/v1alpha/test/accounts/non-admin/subjects/foo",
			Persona: "admin",
			Output:  "^.*not found",
			Status:  http.StatusNotFound,
		},
		{
			Name:    "Get linked accounts (foo@bar.com)",
			Method:  "GET",
			Path:    "/identity/v1alpha/test/accounts/non-admin/subjects/foo@bar.com",
			Persona: "admin",
			Output:  "^.*not found",
			Status:  http.StatusNotFound,
		},
		{
			Name:    "Get account",
			Method:  "GET",
			Path:    "/identity/v1alpha/test/accounts/-",
			Persona: "non-admin",
			Output:  `^.*non-admin@example.org.*"passport"`,
			Status:  http.StatusOK,
		},
	}
	test.HandlerTests(t, s.Handler, tests, oidcIssuer, server.Config())
}

func createTestToken(t *testing.T, s *Service, id *ga4gh.Identity, scope string, cfg *pb.IcConfig) string {
	token, err := s.createToken(id, scope, "", "", "test", noNonce, time.Now(), time.Hour, cfg, nil)
	if err != nil {
		t.Fatalf("creating test token: %v", err)
	}
	return token
}

func TestAdminHandlers(t *testing.T) {
	store := storage.NewMemoryStorage("ic-min", "testdata/config")
	server, err := fakeoidcissuer.New(oidcIssuer, &testkeys.PersonaBrokerKey, "dam-min", "testdata/config")
	if err != nil {
		t.Fatalf("fakeoidcissuer.New(%q, _, _) failed: %v", oidcIssuer, err)
	}
	ctx := server.ContextWithClient(context.Background())

	s := NewService(ctx, domain, domain, hydraAdminURL, store, fakeencryption.New())
	tests := []test.HandlerTest{
		{
			Name:    "List all tokens of all users as a non-admin",
			Method:  "GET",
			Path:    "/identity/v1alpha/test/admin/tokens",
			Persona: "non-admin",
			Output: `^.*user is not an administrator	*`,
			Status: http.StatusForbidden,
		},
		{
			Name:    "List all tokens of all users as an admin",
			Method:  "GET",
			Path:    "/identity/v1alpha/test/admin/tokens",
			Persona: "admin",
			Output:  `{"tokensMetadata":{"dr_joe_elixir/123-456":{"tokenType":"refresh","issuedAt":"1560970669","scope":"ga4gh_passport_v1 identities profiles openid","identityProvider":"elixir"},"someone-account/1a2-3b4":{"tokenType":"refresh","issuedAt":"1560970669","scope":"ga4gh_passport_v1 openid","identityProvider":"google"}}}`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Delete all tokens of all users as a non-admin",
			Method:  "DELETE",
			Path:    "/identity/v1alpha/test/admin/tokens",
			Persona: "non-admin",
			Output: `^.*user is not an administrator	*`,
			Status: http.StatusForbidden,
		},
		{
			Name:    "Delete all tokens of all users as an admin",
			Method:  "DELETE",
			Path:    "/identity/v1alpha/test/admin/tokens",
			Persona: "admin",
			Output:  ``,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get deleted tokens of all users as an admin",
			Method:  "GET",
			Path:    "/identity/v1alpha/test/admin/tokens",
			Persona: "admin",
			Output:  `{}`,
			Status:  http.StatusOK,
		},
	}
	test.HandlerTests(t, s.Handler, tests, oidcIssuer, server.Config())
}

func TestNonce(t *testing.T) {
	nonce := "nonce-for-test"
	store := storage.NewMemoryStorage("ic-min", "testdata/config")
	s := NewService(context.Background(), domain, domain, hydraAdminURL, store, fakeencryption.New())
	cfg, err := s.loadConfig(nil, "test")
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}

	// Auth Code should not include "nonce".
	auth, err := s.createAuthToken("someone-account", "openid", "persona", "test", nonce, time.Now(), cfg, nil)
	if err != nil {
		t.Fatalf("creating auth token: %v", err)
	}
	id, err := common.ConvertTokenToIdentityUnsafe(auth)
	if err != nil {
		t.Fatalf("ConvertTokenToIdentityUnsafe(%q) error: %v", auth, err)
	}
	if len(id.Nonce) > 0 {
		t.Error("Auth Code should not include 'nonce'")
	}

	path := strings.ReplaceAll(tokenPath, "{realm}", "test")

	// ID token request by auth code should include "nonce".
	w := httptest.NewRecorder()
	params := fmt.Sprintf("grant_type=authorization_code&client_id=%s&client_secret=%s&redirect_uri=http://example.com&code=%s", testClientID, testClientSecret, auth)
	r := httptest.NewRequest("POST", path+"?"+params, nil)
	s.Handler.ServeHTTP(w, r)
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("get tokens by auth code want ok, got %q", resp.Status)
	}

	unmarshaler := jsonpb.Unmarshaler{}
	tokens := cpb.OidcTokenResponse{}
	err = unmarshaler.Unmarshal(resp.Body, &tokens)
	if err != nil {
		t.Fatalf("unmarshal failed")
	}
	id, err = common.ConvertTokenToIdentityUnsafe(tokens.IdToken)
	if err != nil {
		t.Errorf("ConvertTokenToIdentityUnsafe(%q) error: %v", tokens.IdToken, err)
	}
	if id.Nonce != nonce {
		t.Errorf("get tokens by auth code, id_token.nonce incorrect: want %q, got %q", id.Nonce, nonce)
	}
	access, err := common.ConvertTokenToIdentityUnsafe(tokens.AccessToken)
	if err != nil {
		t.Errorf("ConvertTokenToIdentityUnsafe(%q) error: %v", tokens.AccessToken, err)
	}
	if len(access.Nonce) > 0 {
		t.Error("access token should not include nonce")
	}
	refresh, err := common.ConvertTokenToIdentityUnsafe(tokens.RefreshToken)
	if err != nil {
		t.Errorf("ConvertTokenToIdentityUnsafe(%q) error: %v", tokens.RefreshToken, err)
	}
	if len(refresh.Nonce) > 0 {
		t.Error("refresh token should not include nonce")
	}

	// ID token request by refresh token should not include "nonce".
	w = httptest.NewRecorder()
	params = fmt.Sprintf("grant_type=refresh_token&client_id=%s&client_secret=%s&redirect_uri=http://example.com&refresh_token=%s", testClientID, testClientSecret, tokens.RefreshToken)
	r = httptest.NewRequest("POST", path+"?"+params, nil)
	s.Handler.ServeHTTP(w, r)
	resp = w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("get tokens by refresh token want ok, got %q", resp.Status)
	}
	err = unmarshaler.Unmarshal(resp.Body, &tokens)
	if err != nil {
		t.Error("unmarshal failed")
	}
	id, err = common.ConvertTokenToIdentityUnsafe(tokens.IdToken)
	if len(id.Nonce) > 0 {
		t.Error("get tokens by refresh token, id token not include nonce")
	}
	access, err = common.ConvertTokenToIdentityUnsafe(tokens.AccessToken)
	if len(access.Nonce) > 0 {
		t.Error("access token should not include nonce")
	}
	refresh, err = common.ConvertTokenToIdentityUnsafe(tokens.RefreshToken)
	if len(refresh.Nonce) > 0 {
		t.Error("refresh token should not include nonce")
	}
}

func TestAddLinkedIdentities(t *testing.T) {
	subject := "111@a.com"
	issuer := "https://example.com/oidc"
	subjectInIdp := "222"
	emailInIdp := "222@idp.com"
	idp := "idp"
	idpIss := "https://idp.com/oidc"

	id := &ga4gh.Identity{
		Subject:  subject,
		Issuer:   issuer,
		VisaJWTs: []string{},
	}

	link := &pb.ConnectedAccount{
		Provider: idp,
		Properties: &pb.AccountProperties{
			Subject: subjectInIdp,
			Email:   emailInIdp,
		},
	}

	store := storage.NewMemoryStorage("ic-min", "testdata/config")
	s := NewService(context.Background(), domain, domain, hydraAdminURL, store, fakeencryption.New())
	cfg, err := s.loadConfig(nil, storage.DefaultRealm)
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}
	cfg.IdentityProviders = map[string]*pb.IdentityProvider{
		idp: &pb.IdentityProvider{Issuer: idpIss},
	}

	err = s.addLinkedIdentities(id, link, testkeys.Default.Private, cfg)
	if err != nil {
		t.Fatalf("s.addLinkedIdentities(_) failed: %v", err)
	}

	if len(id.VisaJWTs) != 1 {
		t.Fatalf("len(id.VisaJWTs), want 1, got %d", len(id.VisaJWTs))
	}

	v, err := ga4gh.NewVisaFromJWT(ga4gh.VisaJWT(id.VisaJWTs[0]))
	if err != nil {
		t.Fatalf("ga4gh.NewVisaFromJWT(_) failed: %v", err)
	}

	got := v.Data()

	wantIdentities := []string{
		linkedIdentityValue(subjectInIdp, idpIss),
		linkedIdentityValue(emailInIdp, idpIss),
	}

	want := &ga4gh.VisaData{
		StdClaims: ga4gh.StdClaims{
			Subject:   subject,
			Issuer:    issuer,
			IssuedAt:  got.IssuedAt,
			ExpiresAt: got.ExpiresAt,
		},
		Scope: "openid",
		Assertion: ga4gh.Assertion{
			Type:     ga4gh.LinkedIdentities,
			Asserted: got.Assertion.Asserted,
			Value:    ga4gh.Value(strings.Join(wantIdentities, ";")),
			Source:   ga4gh.Source(issuer),
		},
	}

	if diff := cmp.Diff(want, got); len(diff) != 0 {
		t.Fatalf("v.Data() returned diff (-want +got):\n%s", diff)
	}
}
