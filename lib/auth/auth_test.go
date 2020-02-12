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

package auth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux" /* copybara-comment */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"golang.org/x/oauth2" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakeoidcissuer" /* copybara-comment: fakeoidcissuer */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test" /* copybara-comment: test */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */
)

const (
	issuerURL = "https://oidc.example.com/"
)

var (
	handlers = map[string]Require{
		"/norequirement":    RequireNone,
		"/clientidonly":     RequireClientID,
		"/clientsecret":     RequireClientIDAndSecret,
		"/usertoken":        RequireUserToken,
		"/usertoken/{user}": RequireUserToken,
		"/admintoken":       RequireAdminToken,
	}
)

func Test_LargeBody(t *testing.T) {
	router, oidc, _, _ := setup(t)
	// Build a big http body
	sb := strings.Builder{}
	for i := 0; i < maxHTTPBody+10; i++ {
		sb.WriteString("a")
	}

	resp := sendRequest(http.MethodPost, "/norequirement", "", "", "", sb.String(), router, oidc)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unexpected status code: %d wants %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func Test_ErrorAtClientSecret(t *testing.T) {
	router, oidc, service, _ := setup(t)
	service.FetchClientSecrets = func() (map[string]string, error) {
		return nil, status.Error(codes.Unavailable, "Unavailable")
	}

	for path, require := range handlers {
		t.Run(path, func(t *testing.T) {
			resp := sendRequest(http.MethodGet, path, "", "", "", "", router, oidc)
			if !require.ClientID {
				if resp.StatusCode != http.StatusOK {
					t.Errorf("unexpected status code: %d want %d", resp.StatusCode, http.StatusOK)
				}
			} else {
				if resp.StatusCode != http.StatusServiceUnavailable {
					t.Errorf("unexpected status code: %d want %d", resp.StatusCode, http.StatusServiceUnavailable)
				}
			}
		})
	}
}

func Test_RequiresClientID(t *testing.T) {
	router, oidc, _, stub := setup(t)

	resp := sendRequest(http.MethodGet, "/clientidonly", test.TestClientID, "", "", "", router, oidc)
	want := "GET /clientidonly"
	if stub.message != want {
		t.Errorf("stub.message=%q wants %q", stub.message, want)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("unexpected status code: %d wants %d", resp.StatusCode, http.StatusOK)
	}
}

func Test_RequiresClientID_Error(t *testing.T) {
	router, oidc, _, _ := setup(t)

	tests := []struct {
		name     string
		clientID string
	}{
		{
			name: "no clientID",
		},
		{
			name:     "clientID invalid",
			clientID: "invalid",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := sendRequest(http.MethodGet, "/clientidonly", tc.clientID, "", "", "", router, oidc)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("unexpected status code: %d want %d", resp.StatusCode, http.StatusUnauthorized)
			}
		})
	}
}

func Test_RequiresClientSecret(t *testing.T) {
	router, oidc, _, stub := setup(t)

	resp := sendRequest(http.MethodGet, "/clientsecret", test.TestClientID, test.TestClientSecret, "", "", router, oidc)
	want := "GET /clientsecret"
	if stub.message != want {
		t.Errorf("stub.message=%q wants %q", stub.message, want)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("unexpected status code: %d wants %d", resp.StatusCode, http.StatusOK)
	}
}

func Test_RequiresClientSecret_Error(t *testing.T) {
	router, oidc, _, _ := setup(t)

	tests := []struct {
		name         string
		clientSecret string
	}{
		{
			name: "no clientSecret",
		},
		{
			name:         "clientSecret no match",
			clientSecret: "invalid",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := sendRequest(http.MethodGet, "/clientsecret", test.TestClientID, tc.clientSecret, "", "", router, oidc)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("unexpected status code: %d want %d", resp.StatusCode, http.StatusUnauthorized)
			}
		})
	}
}

func Test_RequiresToken_Error(t *testing.T) {
	router, oidc, _, _ := setup(t)

	tests := []struct {
		name string
		tok  string
	}{
		{
			name: "no token",
		},
		{
			name: "not a jwt",
			tok:  "invalid",
		},
	}

	paths := []string{"/usertoken", "/usertoken/sub", "/admintoken"}

	for _, tc := range tests {
		for _, p := range paths {
			t.Run(tc.name, func(t *testing.T) {
				resp := sendRequest(http.MethodGet, p, test.TestClientID, test.TestClientSecret, tc.tok, "", router, oidc)
				if resp.StatusCode != http.StatusUnauthorized {
					t.Errorf("unexpected status code: %d want %d", resp.StatusCode, http.StatusUnauthorized)
				}
			})
		}
	}
}

func Test_RequiresToken_JWT_Invalid_Signature(t *testing.T) {
	router, oidc, _, _ := setup(t)

	now := time.Now().Unix()
	claims := &ga4gh.Identity{
		Issuer:    issuerURL,
		Subject:   "sub",
		IssuedAt:  now,
		Expiry:    now + 10000,
		Audiences: ga4gh.NewAudience(test.TestClientID),
	}

	tok, err := oidc.Sign(nil, claims)
	if err != nil {
		t.Fatalf("oidc.Sign() failed: %v", err)
	}

	tok = tok + "invalid"

	paths := []string{"/usertoken", "/usertoken/sub", "/admintoken"}

	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			resp := sendRequest(http.MethodGet, p, test.TestClientID, test.TestClientSecret, tok, "", router, oidc)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("unexpected status code: %d wants %d", resp.StatusCode, http.StatusUnauthorized)
			}
		})
	}
}

func Test_RequiresToken_JWT_Claims_Invalid(t *testing.T) {
	router, oidc, _, _ := setup(t)

	now := time.Now().Unix()
	tests := []struct {
		name   string
		claims *ga4gh.Identity
	}{
		{
			name: "no subject",
			claims: &ga4gh.Identity{
				Issuer:    issuerURL,
				IssuedAt:  now,
				Expiry:    now + 10000,
				Audiences: ga4gh.NewAudience(test.TestClientID),
			},
		},
		{
			name: "expired",
			claims: &ga4gh.Identity{
				Issuer:    issuerURL,
				Subject:   "sub",
				IssuedAt:  now - 100000,
				Expiry:    now - 10000,
				Audiences: ga4gh.NewAudience(test.TestClientID),
			},
		},
		{
			name: "future token",
			claims: &ga4gh.Identity{
				Issuer:    issuerURL,
				Subject:   "sub",
				IssuedAt:  now + 10000,
				Expiry:    now + 100000,
				Audiences: ga4gh.NewAudience(test.TestClientID),
			},
		},
		{
			name: "clientID in token not match in request",
			claims: &ga4gh.Identity{
				Issuer:    issuerURL,
				Subject:   "sub",
				IssuedAt:  now,
				Expiry:    now + 10000,
				Audiences: ga4gh.NewAudience("invalid"),
			},
		},
		{
			name: "issuer not match",
			claims: &ga4gh.Identity{
				Issuer:    issuerURL + "invalid/",
				Subject:   "sub",
				IssuedAt:  now,
				Expiry:    now + 10000,
				Audiences: ga4gh.NewAudience(test.TestClientID),
			},
		},
	}

	paths := []string{"/usertoken", "/usertoken/sub", "/admintoken"}

	for _, tc := range tests {
		for _, p := range paths {
			t.Run(tc.name+" "+p, func(t *testing.T) {
				tok, err := oidc.Sign(nil, tc.claims)
				if err != nil {
					t.Fatalf("oidc.Sign() failed: %v", err)
				}

				resp := sendRequest(http.MethodGet, p, test.TestClientID, test.TestClientSecret, tok, "", router, oidc)
				if resp.StatusCode != http.StatusUnauthorized {
					t.Errorf("unexpected status code: %d want %d", resp.StatusCode, http.StatusUnauthorized)
				}
			})
		}
	}
}

func Test_RequiresUserToken(t *testing.T) {
	router, oidc, _, stub := setup(t)

	now := time.Now().Unix()
	claims := &ga4gh.Identity{
		Issuer:    issuerURL,
		Subject:   "sub",
		IssuedAt:  now,
		Expiry:    now + 10000,
		Audiences: ga4gh.NewAudience(test.TestClientID),
	}

	tok, err := oidc.Sign(nil, claims)
	if err != nil {
		t.Fatalf("oidc.Sign() failed: %v", err)
	}

	paths := []string{"/usertoken", "/usertoken/sub"}

	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			resp := sendRequest(http.MethodGet, p, test.TestClientID, test.TestClientSecret, tok, "", router, oidc)
			want := "GET " + p
			if stub.message != want {
				t.Errorf("stub.message=%q wants %q", stub.message, want)
			}

			if resp.StatusCode != http.StatusOK {
				t.Errorf("unexpected status code: %d wants %d", resp.StatusCode, http.StatusOK)
			}
		})
	}
}

func Test_RequiresUserToken_UserNotMatch(t *testing.T) {
	router, oidc, _, _ := setup(t)

	now := time.Now().Unix()
	claims := &ga4gh.Identity{
		Issuer:    issuerURL,
		Subject:   "sub",
		IssuedAt:  now,
		Expiry:    now + 10000,
		Audiences: ga4gh.NewAudience(test.TestClientID),
	}

	tok, err := oidc.Sign(nil, claims)
	if err != nil {
		t.Fatalf("oidc.Sign() failed: %v", err)
	}

	paths := []string{"/usertoken/someone_else"}

	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			resp := sendRequest(http.MethodGet, p, test.TestClientID, test.TestClientSecret, tok, "", router, oidc)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("unexpected status code: %d wants %d", resp.StatusCode, http.StatusUnauthorized)
			}
		})
	}
}

func Test_RequiresAdminToken(t *testing.T) {
	router, oidc, _, stub := setup(t)

	now := time.Now().Unix()
	claims := &ga4gh.Identity{
		Issuer:    issuerURL,
		Subject:   "admin",
		IssuedAt:  now,
		Expiry:    now + 10000,
		Audiences: ga4gh.NewAudience(test.TestClientID),
	}

	tok, err := oidc.Sign(nil, claims)
	if err != nil {
		t.Fatalf("oidc.Sign() failed: %v", err)
	}

	paths := []string{"/admintoken"}

	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			resp := sendRequest(http.MethodGet, p, test.TestClientID, test.TestClientSecret, tok, "", router, oidc)
			want := "GET " + p
			if stub.message != want {
				t.Errorf("stub.message=%q wants %q", stub.message, want)
			}

			if resp.StatusCode != http.StatusOK {
				t.Errorf("unexpected status code: %d wants %d", resp.StatusCode, http.StatusOK)
			}
		})
	}
}

func Test_RequiresAdminToken_Error(t *testing.T) {
	router, oidc, _, _ := setup(t)

	now := time.Now().Unix()
	claims := &ga4gh.Identity{
		Issuer:    issuerURL,
		Subject:   "sub",
		IssuedAt:  now,
		Expiry:    now + 10000,
		Audiences: ga4gh.NewAudience(test.TestClientID),
	}

	tok, err := oidc.Sign(nil, claims)
	if err != nil {
		t.Fatalf("oidc.Sign() failed: %v", err)
	}

	paths := []string{"/admintoken"}

	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			resp := sendRequest(http.MethodGet, p, test.TestClientID, test.TestClientSecret, tok, "", router, oidc)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("unexpected status code: %d wants %d", resp.StatusCode, http.StatusUnauthorized)
			}
		})
	}
}

func Test_normalize(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "http://example.com/",
			want:  "http://example.com",
		},
		{
			input: "http://example.com",
			want:  "http://example.com",
		},
	}

	for _, tc := range tests {
		got := normalize(tc.input)
		if got != tc.want {
			t.Errorf("normalize(%s) = %s wants %s", tc.input, got, tc.want)
		}
	}
}

func setup(t *testing.T) (*mux.Router, *fakeoidcissuer.Server, *Checker, *handlerFuncStub) {
	t.Helper()

	oidc, err := fakeoidcissuer.New(issuerURL, &testkeys.PersonaBrokerKey, "dam-min", "testdata/config", false)
	if err != nil {
		t.Fatalf("fakeoidcissuer.New(%q, _, _, _, _) failed: %v", issuerURL, err)
	}

	c := &Checker{
		Issuer:             issuerURL,
		FetchClientSecrets: clientSecrets,
		TransformIdentity:  transformIdentity,
		IsAdmin:            isAdmin,
	}

	stub := &handlerFuncStub{}

	r := mux.NewRouter()

	for k, v := range handlers {
		h, err := WithAuth(stub.handle, c, v)
		if err != nil {
			t.Fatalf("WithAuth(_, _, %v) failed for %s: %v", v, k, err)
		}
		r.HandleFunc(k, h)
	}

	return r, oidc, c, stub
}

func sendRequest(method, path, clientID, clientSecret, token, body string, handler http.Handler, oidc *fakeoidcissuer.Server) *http.Response {
	var br io.Reader
	if len(body) != 0 {
		br = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, path, br)
	q := url.Values{}

	if len(clientID) != 0 {
		q.Add("client_id", clientID)
	}

	if len(clientSecret) != 0 {
		q.Add("client_secret", clientSecret)
	}

	r.URL.RawQuery = q.Encode()

	if len(token) != 0 {
		r.Header.Add("Authorization", "bearer "+token)
	}

	r = r.WithContext(context.WithValue(r.Context(), oauth2.HTTPClient, oidc.Client()))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w.Result()
}

func clientSecrets() (map[string]string, error) {
	return map[string]string{test.TestClientID: test.TestClientSecret}, nil
}

func transformIdentity(id *ga4gh.Identity) *ga4gh.Identity {
	return id
}

func isAdmin(id *ga4gh.Identity) error {
	if id.Subject == "admin" {
		return nil
	}

	return fmt.Errorf("not admin")
}

type handlerFuncStub struct {
	message string
}

func (s *handlerFuncStub) handle(w http.ResponseWriter, r *http.Request) {
	s.message = r.Method + " " + r.URL.Path
}
