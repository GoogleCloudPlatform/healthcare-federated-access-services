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
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"github.com/gorilla/mux" /* copybara-comment */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"golang.org/x/oauth2" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/permissions" /* copybara-comment: permissions */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakeoidcissuer" /* copybara-comment: fakeoidcissuer */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakesdl" /* copybara-comment: fakesdl */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test" /* copybara-comment: test */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/verifier" /* copybara-comment: verifier */

	hrpb "google.golang.org/genproto/googleapis/logging/type" /* copybara-comment: http_request_go_proto */
	lspb "google.golang.org/genproto/googleapis/logging/type" /* copybara-comment: log_severity_go_proto */
	lepb "google.golang.org/genproto/googleapis/logging/v2" /* copybara-comment: log_entry_go_proto */
)

const (
	issuerURL = "https://oidc.example.com/"

	verifierErrParseFailed      = "token:parse_failed"
	verifierErrSubMissing       = "token:sub_missing"
	verifierErrIssuerNotMatch   = "token:issuer_not_match"
	verifierErrInvalidSignature = "token:invalid_signature"
	verifierErrInvalidAudience  = "token:invalid_aud"
	verifierErrExpired          = "token:expired"
	verifierErrFutureToken      = "token:future_token"
)

var (
	handlers = map[string]Require{
		"/norequirement":    RequireNone,
		"/clientidonly":     RequireClientID,
		"/clientsecret":     RequireClientIDAndSecret,
		"/usertoken":        RequireUserToken,
		"/usertoken/{user}": RequireUserToken,
		"/admintoken":       RequireAdminToken,
		"/auditlog/{name}":  RequireUserToken,
		"/acctadmin/{name}": RequireAccountAdminUserToken,
	}
)

func Test_LargeBody(t *testing.T) {
	router, oidc, _, _, _, close := setup(t)
	defer close()
	// Build a big http body
	sb := strings.Builder{}
	for i := 0; i < maxHTTPBody+10; i++ {
		sb.WriteString("a")
	}

	resp := sendRequest(http.MethodPost, "/norequirement", "", "", "", "", sb.String(), router, oidc)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unexpected status code: %d wants %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func Test_LargeBody_Log(t *testing.T) {
	router, oidc, _, _, logs, close := setup(t)
	defer close()
	// Build a big http body
	sb := strings.Builder{}
	for i := 0; i < maxHTTPBody+10; i++ {
		sb.WriteString("a")
	}

	sendRequest(http.MethodPost, "/norequirement", "", "", "", "", sb.String(), router, oidc)

	ets := errTypesFromLogs(logs)
	wantErrType := []errType{errBodyTooLarge}
	if diff := cmp.Diff(wantErrType, ets); len(diff) != 0 {
		t.Errorf("error_type (-want +got): %s", diff)
	}
}

func Test_ErrorAtClientSecret(t *testing.T) {
	for path, require := range handlers {
		t.Run(path, func(t *testing.T) {
			router, oidc, service, _, _, close := setup(t)
			defer close()

			service.fetchClientSecrets = func() (map[string]string, error) {
				return nil, status.Error(codes.Unavailable, "Unavailable")
			}

			resp := sendRequest(http.MethodGet, path, "", "", "", "", "", router, oidc)
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

func Test_ErrorAtClientSecret_Log(t *testing.T) {
	for path, require := range handlers {
		t.Run(path, func(t *testing.T) {
			router, oidc, service, _, logs, close := setup(t)
			defer close()

			service.fetchClientSecrets = func() (map[string]string, error) {
				return nil, status.Error(codes.Unavailable, "Unavailable")
			}

			sendRequest(http.MethodGet, path, "", "", "", "", "", router, oidc)
			if !require.ClientID {
				ets := errTypesFromLogs(logs)
				wantErrType := []errType{""}
				if diff := cmp.Diff(wantErrType, ets); len(diff) != 0 {
					t.Errorf("error_type (-want +got): %s", diff)
				}
			} else {
				ets := errTypesFromLogs(logs)
				wantErrType := []errType{errClientUnavailable}
				if diff := cmp.Diff(wantErrType, ets); len(diff) != 0 {
					t.Errorf("error_type (-want +got): %s", diff)
				}
			}
		})
	}
}

func Test_RequiresClientID(t *testing.T) {
	router, oidc, _, stub, _, close := setup(t)
	defer close()

	resp := sendRequest(http.MethodGet, "/clientidonly", test.TestClientID, "", "", "", "", router, oidc)
	want := "GET /clientidonly"
	if stub.message != want {
		t.Errorf("stub.message=%q wants %q", stub.message, want)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("unexpected status code: %d wants %d", resp.StatusCode, http.StatusOK)
	}
}

func Test_RequiresClientID_Log(t *testing.T) {
	router, oidc, _, _, logs, close := setup(t)
	defer close()

	sendRequest(http.MethodGet, "/clientidonly", test.TestClientID, "", "", "", "", router, oidc)

	ets := errTypesFromLogs(logs)
	wantErrType := []errType{""}
	if diff := cmp.Diff(wantErrType, ets); len(diff) != 0 {
		t.Errorf("error_type (-want +got): %s", diff)
	}
}

func Test_RequiresClientID_Error(t *testing.T) {
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
			router, oidc, _, _, _, close := setup(t)
			defer close()

			resp := sendRequest(http.MethodGet, "/clientidonly", tc.clientID, "", "", "", "", router, oidc)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("unexpected status code: %d want %d", resp.StatusCode, http.StatusUnauthorized)
			}
		})
	}
}

func Test_RequiresClientID_Error_Log(t *testing.T) {
	tests := []struct {
		name     string
		clientID string
		et       errType
	}{
		{
			name: "no clientID",
			et:   errClientMissing,
		},
		{
			name:     "clientID invalid",
			clientID: "invalid",
			et:       errClientInvalid,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			router, oidc, _, _, logs, close := setup(t)
			defer close()

			resp := sendRequest(http.MethodGet, "/clientidonly", tc.clientID, "", "", "", "", router, oidc)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("unexpected status code: %d want %d", resp.StatusCode, http.StatusUnauthorized)
			}

			ets := errTypesFromLogs(logs)
			wantErrType := []errType{tc.et}
			if diff := cmp.Diff(wantErrType, ets); len(diff) != 0 {
				t.Errorf("error_type (-want +got): %s", diff)
			}
		})
	}
}

func Test_RequiresClientSecret(t *testing.T) {
	router, oidc, _, stub, _, close := setup(t)
	defer close()

	resp := sendRequest(http.MethodGet, "/clientsecret", test.TestClientID, test.TestClientSecret, "", "", "", router, oidc)
	want := "GET /clientsecret"
	if stub.message != want {
		t.Errorf("stub.message=%q wants %q", stub.message, want)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("unexpected status code: %d wants %d", resp.StatusCode, http.StatusOK)
	}
}

func Test_RequiresClientSecret_Log(t *testing.T) {
	router, oidc, _, _, logs, close := setup(t)
	defer close()

	sendRequest(http.MethodGet, "/clientsecret", test.TestClientID, test.TestClientSecret, "", "", "", router, oidc)

	ets := errTypesFromLogs(logs)
	wantErrType := []errType{""}
	if diff := cmp.Diff(wantErrType, ets); len(diff) != 0 {
		t.Errorf("error_type (-want +got): %s", diff)
	}
}

func Test_RequiresClientSecret_Error(t *testing.T) {
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
			router, oidc, _, _, _, close := setup(t)
			defer close()

			resp := sendRequest(http.MethodGet, "/clientsecret", test.TestClientID, tc.clientSecret, "", "", "", router, oidc)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("unexpected status code: %d want %d", resp.StatusCode, http.StatusUnauthorized)
			}
		})
	}
}

func Test_RequiresClientSecret_Error_Log(t *testing.T) {
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
			router, oidc, _, _, logs, close := setup(t)
			defer close()

			sendRequest(http.MethodGet, "/clientsecret", test.TestClientID, tc.clientSecret, "", "", "", router, oidc)

			ets := errTypesFromLogs(logs)
			wantErrType := []errType{errSecretMismatch}
			if diff := cmp.Diff(wantErrType, ets); len(diff) != 0 {
				t.Errorf("error_type (-want +got): %s", diff)
			}
		})
	}
}

func Test_RequiresToken_Error(t *testing.T) {
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
			t.Run(tc.name+" "+p, func(t *testing.T) {
				router, oidc, _, _, _, close := setup(t)
				defer close()

				resp := sendRequest(http.MethodGet, p, test.TestClientID, test.TestClientSecret, tc.tok, "", "", router, oidc)
				if resp.StatusCode != http.StatusUnauthorized {
					t.Errorf("unexpected status code: %d want %d", resp.StatusCode, http.StatusUnauthorized)
				}
			})
		}
	}
}

func Test_RequiresToken_Error_Log(t *testing.T) {
	tests := []struct {
		name string
		tok  string
		et   errType
	}{
		{
			name: "no token",
			et:   errIDVerifyFailed,
		},
		{
			name: "not a jwt",
			tok:  "invalid",
			et:   verifierErrParseFailed,
		},
	}

	paths := []string{"/usertoken", "/usertoken/sub", "/admintoken"}

	for _, tc := range tests {
		for _, p := range paths {
			t.Run(tc.name+" "+p, func(t *testing.T) {
				router, oidc, _, _, logs, close := setup(t)
				defer close()

				sendRequest(http.MethodGet, p, test.TestClientID, test.TestClientSecret, tc.tok, "", "", router, oidc)

				ets := errTypesFromLogs(logs)
				wantErrType := []errType{tc.et}
				if diff := cmp.Diff(wantErrType, ets); len(diff) != 0 {
					t.Errorf("error_type (-want +got): %s", diff)
				}
			})
		}
	}
}

func Test_RequiresToken_JWT_Invalid_Signature(t *testing.T) {
	now := time.Now().Unix()
	claims := &ga4gh.Identity{
		Issuer:    issuerURL,
		Subject:   "sub",
		IssuedAt:  now,
		Expiry:    now + 10000,
		Audiences: ga4gh.NewAudience(test.TestClientID),
	}

	paths := []string{"/usertoken", "/usertoken/sub", "/admintoken"}

	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			router, oidc, _, _, _, close := setup(t)
			defer close()

			tok, err := oidc.Sign(nil, claims)
			if err != nil {
				t.Fatalf("oidc.Sign() failed: %v", err)
			}

			tok = tok + "invalid"

			resp := sendRequest(http.MethodGet, p, test.TestClientID, test.TestClientSecret, tok, "", "", router, oidc)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("unexpected status code: %d wants %d", resp.StatusCode, http.StatusUnauthorized)
			}
		})
	}
}

func Test_RequiresToken_JWT_Invalid_Signature_Log(t *testing.T) {
	now := time.Now().Unix()
	claims := &ga4gh.Identity{
		Issuer:    issuerURL,
		Subject:   "sub",
		IssuedAt:  now,
		Expiry:    now + 10000,
		Audiences: ga4gh.NewAudience(test.TestClientID),
	}

	paths := []string{"/usertoken", "/usertoken/sub", "/admintoken"}

	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			router, oidc, _, _, logs, close := setup(t)
			defer close()

			tok, err := oidc.Sign(nil, claims)
			if err != nil {
				t.Fatalf("oidc.Sign() failed: %v", err)
			}

			tok = tok + "invalid"

			sendRequest(http.MethodGet, p, test.TestClientID, test.TestClientSecret, tok, "", "", router, oidc)

			ets := errTypesFromLogs(logs)
			wantErrType := []errType{verifierErrInvalidSignature}
			if diff := cmp.Diff(wantErrType, ets); len(diff) != 0 {
				t.Errorf("error_type (-want +got): %s", diff)
			}
		})
	}
}

func Test_RequiresToken_JWT_Claims_Invalid(t *testing.T) {
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
				router, oidc, _, _, _, close := setup(t)
				defer close()

				tok, err := oidc.Sign(nil, tc.claims)
				if err != nil {
					t.Fatalf("oidc.Sign() failed: %v", err)
				}

				resp := sendRequest(http.MethodGet, p, test.TestClientID, test.TestClientSecret, tok, "", "", router, oidc)
				if resp.StatusCode != http.StatusUnauthorized {
					t.Errorf("unexpected status code: %d want %d", resp.StatusCode, http.StatusUnauthorized)
				}
			})
		}
	}
}

func Test_RequiresToken_JWT_Claims_Invalid_Error(t *testing.T) {
	now := time.Now().Unix()
	tests := []struct {
		name   string
		claims *ga4gh.Identity
		et     errType
	}{
		{
			name: "no subject",
			claims: &ga4gh.Identity{
				Issuer:    issuerURL,
				IssuedAt:  now,
				Expiry:    now + 10000,
				Audiences: ga4gh.NewAudience(test.TestClientID),
			},
			et: verifierErrSubMissing,
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
			et: verifierErrExpired,
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
			et: verifierErrFutureToken,
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
			et: verifierErrInvalidAudience,
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
			et: verifierErrIssuerNotMatch,
		},
	}

	paths := []string{"/usertoken", "/usertoken/sub", "/admintoken"}

	for _, tc := range tests {
		for _, p := range paths {
			t.Run(tc.name+" "+p, func(t *testing.T) {
				router, oidc, _, _, logs, close := setup(t)
				defer close()

				tok, err := oidc.Sign(nil, tc.claims)
				if err != nil {
					t.Fatalf("oidc.Sign() failed: %v", err)
				}

				sendRequest(http.MethodGet, p, test.TestClientID, test.TestClientSecret, tok, "", "", router, oidc)

				ets := errTypesFromLogs(logs)
				wantErrType := []errType{tc.et}
				if diff := cmp.Diff(wantErrType, ets); len(diff) != 0 {
					t.Errorf("error_type (-want +got): %s", diff)
				}
			})
		}
	}
}

func Test_RequiresUserToken(t *testing.T) {
	now := time.Now().Unix()
	claims := &ga4gh.Identity{
		Issuer:    issuerURL,
		Subject:   "sub",
		IssuedAt:  now,
		Expiry:    now + 10000,
		Audiences: ga4gh.NewAudience(test.TestClientID),
	}

	paths := []string{"/usertoken", "/usertoken/sub"}

	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			router, oidc, _, stub, _, close := setup(t)
			defer close()

			tok, err := oidc.Sign(nil, claims)
			if err != nil {
				t.Fatalf("oidc.Sign() failed: %v", err)
			}

			resp := sendRequest(http.MethodGet, p, test.TestClientID, test.TestClientSecret, tok, "", "", router, oidc)
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

func Test_RequiresUserToken_Log(t *testing.T) {
	now := time.Now().Unix()
	claims := &ga4gh.Identity{
		Issuer:    issuerURL,
		Subject:   "sub",
		IssuedAt:  now,
		Expiry:    now + 10000,
		Audiences: ga4gh.NewAudience(test.TestClientID),
	}

	paths := []string{"/usertoken", "/usertoken/sub"}

	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			router, oidc, _, _, logs, close := setup(t)
			defer close()

			tok, err := oidc.Sign(nil, claims)
			if err != nil {
				t.Fatalf("oidc.Sign() failed: %v", err)
			}

			sendRequest(http.MethodGet, p, test.TestClientID, test.TestClientSecret, tok, "", "", router, oidc)

			ets := errTypesFromLogs(logs)
			wantErrType := []errType{""}
			if diff := cmp.Diff(wantErrType, ets); len(diff) != 0 {
				t.Errorf("error_type (-want +got): %s", diff)
			}
		})
	}
}

func Test_RequiresUserToken_UserMisatch(t *testing.T) {
	router, oidc, _, _, _, close := setup(t)
	defer close()

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

	resp := sendRequest(http.MethodGet, "/usertoken/someone_else", test.TestClientID, test.TestClientSecret, tok, "", "", router, oidc)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unexpected status code: %d wants %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func Test_RequiresUserToken_UserMismatch_Log(t *testing.T) {
	router, oidc, _, _, logs, close := setup(t)
	defer close()

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

	sendRequest(http.MethodGet, "/usertoken/someone_else", test.TestClientID, test.TestClientSecret, tok, "", "", router, oidc)

	ets := errTypesFromLogs(logs)
	wantErrType := []errType{errUserMismatch}
	if diff := cmp.Diff(wantErrType, ets); len(diff) != 0 {
		t.Errorf("error_type (-want +got): %s", diff)
	}
}

func Test_RequiresAdminToken(t *testing.T) {
	router, oidc, _, stub, _, close := setup(t)
	defer close()

	now := time.Now().Unix()
	claims := &ga4gh.Identity{
		Issuer:    issuerURL,
		Subject:   "admin@example.com",
		IssuedAt:  now,
		Expiry:    now + 10000,
		Audiences: ga4gh.NewAudience(test.TestClientID),
	}

	tok, err := oidc.Sign(nil, claims)
	if err != nil {
		t.Fatalf("oidc.Sign() failed: %v", err)
	}

	resp := sendRequest(http.MethodGet, "/admintoken", test.TestClientID, test.TestClientSecret, tok, "", "", router, oidc)
	want := "GET /admintoken"
	if stub.message != want {
		t.Errorf("stub.message=%q wants %q", stub.message, want)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("unexpected status code: %d wants %d", resp.StatusCode, http.StatusOK)
	}
}

func Test_RequiresAdminToken_Log(t *testing.T) {
	router, oidc, _, _, logs, close := setup(t)
	defer close()

	now := time.Now().Unix()
	claims := &ga4gh.Identity{
		Issuer:    issuerURL,
		Subject:   "admin@example.com",
		IssuedAt:  now,
		Expiry:    now + 10000,
		Audiences: ga4gh.NewAudience(test.TestClientID),
	}

	tok, err := oidc.Sign(nil, claims)
	if err != nil {
		t.Fatalf("oidc.Sign() failed: %v", err)
	}

	sendRequest(http.MethodGet, "/admintoken", test.TestClientID, test.TestClientSecret, tok, "", "", router, oidc)

	ets := errTypesFromLogs(logs)
	wantErrType := []errType{""}
	if diff := cmp.Diff(wantErrType, ets); len(diff) != 0 {
		t.Errorf("error_type (-want +got): %s", diff)
	}
}

func Test_RequiresAdminToken_Error(t *testing.T) {
	router, oidc, _, _, _, close := setup(t)
	defer close()

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

	resp := sendRequest(http.MethodGet, "/admintoken", test.TestClientID, test.TestClientSecret, tok, "", "", router, oidc)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unexpected status code: %d wants %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func Test_RequiresAdminToken_Error_Log(t *testing.T) {
	router, oidc, _, _, logs, close := setup(t)
	defer close()

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

	sendRequest(http.MethodGet, "/admintoken", test.TestClientID, test.TestClientSecret, tok, "", "", router, oidc)

	ets := errTypesFromLogs(logs)
	wantErrType := []errType{errNotAdmin}
	if diff := cmp.Diff(wantErrType, ets); len(diff) != 0 {
		t.Errorf("error_type (-want +got): %s", diff)
	}
}

func Test_RequiresAccountAdminUserToken(t *testing.T) {
	now := time.Now().Unix()
	claims := &ga4gh.Identity{
		Issuer:    issuerURL,
		Subject:   "sub",
		Scope:     "openid account_admin offline",
		IssuedAt:  now,
		Expiry:    now + 10000,
		Audiences: ga4gh.NewAudience(test.TestClientID),
	}

	router, oidc, _, stub, _, close := setup(t)
	defer close()

	tok, err := oidc.Sign(nil, claims)
	if err != nil {
		t.Fatalf("oidc.Sign() failed: %v", err)
	}

	path := "/acctadmin/sub"
	resp := sendRequest(http.MethodPost, path, test.TestClientID, test.TestClientSecret, tok, "", "", router, oidc)
	want := "POST " + path
	if stub.message != want {
		t.Errorf("stub.message=%q wants %q", stub.message, want)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("unexpected status code: %d wants %d", resp.StatusCode, http.StatusOK)
	}
}

func Test_RequiresAccountAdminUserToken_Log(t *testing.T) {
	now := time.Now().Unix()
	claims := &ga4gh.Identity{
		Issuer:    issuerURL,
		Subject:   "sub",
		Scope:     "openid account_admin offline",
		IssuedAt:  now,
		Expiry:    now + 10000,
		Audiences: ga4gh.NewAudience(test.TestClientID),
	}

	router, oidc, _, _, logs, close := setup(t)
	defer close()

	tok, err := oidc.Sign(nil, claims)
	if err != nil {
		t.Fatalf("oidc.Sign() failed: %v", err)
	}

	path := "/acctadmin/sub"
	sendRequest(http.MethodPost, path, test.TestClientID, test.TestClientSecret, tok, "", "", router, oidc)

	ets := errTypesFromLogs(logs)
	wantErrType := []errType{""}
	if diff := cmp.Diff(wantErrType, ets); len(diff) != 0 {
		t.Errorf("error_type (-want +got): %s", diff)
	}
}

func Test_RequiresAccountAdminUserToken_Error(t *testing.T) {
	now := time.Now().Unix()
	claims := &ga4gh.Identity{
		Issuer:    issuerURL,
		Subject:   "sub",
		Scope:     "openid offline",
		IssuedAt:  now,
		Expiry:    now + 10000,
		Audiences: ga4gh.NewAudience(test.TestClientID),
	}

	router, oidc, _, _, _, close := setup(t)
	defer close()

	tok, err := oidc.Sign(nil, claims)
	if err != nil {
		t.Fatalf("oidc.Sign() failed: %v", err)
	}

	resp := sendRequest(http.MethodPost, "/acctadmin/sub", test.TestClientID, test.TestClientSecret, tok, "", "", router, oidc)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unexpected status code: %d want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func Test_RequiresAccountAdminUserToken_Error_Log(t *testing.T) {
	now := time.Now().Unix()
	claims := &ga4gh.Identity{
		Issuer:    issuerURL,
		Subject:   "sub",
		Scope:     "openid offline",
		IssuedAt:  now,
		Expiry:    now + 10000,
		Audiences: ga4gh.NewAudience(test.TestClientID),
	}

	router, oidc, _, _, logs, close := setup(t)
	defer close()

	tok, err := oidc.Sign(nil, claims)
	if err != nil {
		t.Fatalf("oidc.Sign() failed: %v", err)
	}

	sendRequest(http.MethodPost, "/acctadmin/sub", test.TestClientID, test.TestClientSecret, tok, "", "", router, oidc)

	ets := errTypesFromLogs(logs)
	wantErrType := []errType{errScopeMissing}
	if diff := cmp.Diff(wantErrType, ets); len(diff) != 0 {
		t.Errorf("error_type (-want +got): %s", diff)
	}
}

func Test_UserAndLinkToken(t *testing.T) {
	now := time.Now().Unix()
	claims := &ga4gh.Identity{
		Issuer:    issuerURL,
		Subject:   "sub",
		Scope:     "openid offline link",
		IssuedAt:  now,
		Expiry:    now + 10000,
		Audiences: ga4gh.NewAudience(test.TestClientID),
	}

	router, oidc, _, stub, _, close := setup(t)
	defer close()

	tok, err := oidc.Sign(nil, claims)
	if err != nil {
		t.Fatalf("oidc.Sign() failed: %v", err)
	}

	headers := map[string]string{
		"Authorization":        "bearer " + tok,
		"X-Link-Authorization": "bearer " + tok,
	}

	path := "/usertoken/sub"
	resp := sendRequestWithHeaders(http.MethodPost, path, test.TestClientID, test.TestClientSecret, "", headers, router, oidc)
	want := "POST " + path
	if stub.message != want {
		t.Errorf("stub.message=%q wants %q", stub.message, want)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("unexpected status code: %d wants %d", resp.StatusCode, http.StatusOK)
	}
}

func Test_UserAndLinkToken_Error(t *testing.T) {
	now := time.Now().Unix()
	claims := &ga4gh.Identity{
		Issuer:    issuerURL,
		Subject:   "sub",
		Scope:     "openid offline",
		IssuedAt:  now,
		Expiry:    now + 10000,
		Audiences: ga4gh.NewAudience(test.TestClientID),
	}

	router, oidc, _, _, _, close := setup(t)
	defer close()

	tok, err := oidc.Sign(nil, claims)
	if err != nil {
		t.Fatalf("oidc.Sign() failed: %v", err)
	}

	headers := map[string]string{
		"Authorization":        "bearer " + tok,
		"X-Link-Authorization": "bearer " + tok,
	}

	resp := sendRequestWithHeaders(http.MethodPost, "/usertoken/sub", test.TestClientID, test.TestClientSecret, "", headers, router, oidc)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unexpected status code: %d wants %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func Test_UserAndLinkToken_Error_Log(t *testing.T) {
	now := time.Now().Unix()
	claims := &ga4gh.Identity{
		Issuer:    issuerURL,
		Subject:   "sub",
		Scope:     "openid offline",
		IssuedAt:  now,
		Expiry:    now + 10000,
		Audiences: ga4gh.NewAudience(test.TestClientID),
	}

	router, oidc, _, _, logs, close := setup(t)
	defer close()

	tok, err := oidc.Sign(nil, claims)
	if err != nil {
		t.Fatalf("oidc.Sign() failed: %v", err)
	}

	headers := map[string]string{
		"Authorization":        "bearer " + tok,
		"X-Link-Authorization": "bearer " + tok,
	}

	sendRequestWithHeaders(http.MethodPost, "/usertoken/sub", test.TestClientID, test.TestClientSecret, "", headers, router, oidc)

	ets := errTypesFromLogs(logs)
	wantErrType := []errType{errScopeMissing}
	if diff := cmp.Diff(wantErrType, ets); len(diff) != 0 {
		t.Errorf("error_type (-want +got): %s", diff)
	}
}

func Test_writeAccessLog_auth_pass(t *testing.T) {
	now := time.Now().Unix()

	tests := []struct {
		name   string
		claims *ga4gh.Identity
	}{
		{
			name: "tid in extra",
			claims: &ga4gh.Identity{
				Issuer:    issuerURL,
				Subject:   "sub",
				IssuedAt:  now,
				Expiry:    now + 10000,
				Audiences: ga4gh.NewAudience(test.TestClientID),
				Extra:     map[string]interface{}{"tid": "id"},
				ID:        "id1",
				TokenID:   "id2",
			},
		},
		{
			name: "tid in top level",
			claims: &ga4gh.Identity{
				Issuer:    issuerURL,
				Subject:   "sub",
				IssuedAt:  now,
				Expiry:    now + 10000,
				Audiences: ga4gh.NewAudience(test.TestClientID),
				ID:        "id1",
				TokenID:   "id",
			},
		},
		{
			name: "no tid use jti",
			claims: &ga4gh.Identity{
				Issuer:    issuerURL,
				Subject:   "sub",
				IssuedAt:  now,
				Expiry:    now + 10000,
				Audiences: ga4gh.NewAudience(test.TestClientID),
				Extra:     map[string]interface{}{"tid": "id"},
				ID:        "id",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			router, oidc, _, _, logs, close := setup(t)
			defer close()

			tok, err := oidc.Sign(nil, tc.claims)
			if err != nil {
				t.Fatalf("oidc.Sign() failed: %v", err)
			}

			tracingID := "1"

			sendRequest(http.MethodGet, "/auditlog/a", test.TestClientID, test.TestClientSecret, tok, tracingID, "", router, oidc)
			logs.Client.Close()

			want := &lepb.LogEntry{
				Payload:  &lepb.LogEntry_JsonPayload{},
				Severity: lspb.LogSeverity_DEFAULT,
				Labels: map[string]string{
					"error_type":      "",
					"tracing_id":      tracingID,
					"request_path":    "/auditlog/{name}",
					"token_id":        "id",
					"token_subject":   "sub",
					"token_issuer":    normalize(issuerURL),
					"type":            "access_log",
					"pass_auth_check": "true",
					"project_id":      "unset-serviceinfo-Project",
					"service_type":    "unset-serviceinfo-Type",
					"service_name":    "unset-serviceinfo-Name",
				},
				HttpRequest: &hrpb.HttpRequest{
					RequestUrl:    "/auditlog/a?client_id=" + test.TestClientID + "&client_secret=" + test.TestClientSecret,
					RequestMethod: http.MethodGet,
					RemoteIp:      "192.168.1.2",
				},
			}

			got := logs.Server.Logs[0].Entries[0]

			got.Timestamp = nil
			if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
				t.Fatalf("Logs returned diff (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_writeAccessLog_auth_failed(t *testing.T) {
	router, oidc, _, _, logs, close := setup(t)
	defer close()

	tracingID := "1"
	sendRequest(http.MethodGet, "/auditlog/a", "", "", "", tracingID, "", router, oidc)
	logs.Client.Close()

	want := &lepb.LogEntry{
		Payload:  &lepb.LogEntry_TextPayload{TextPayload: "rpc error: code = Unauthenticated desc = requires a valid client ID"},
		Severity: lspb.LogSeverity_DEFAULT,
		Labels: map[string]string{
			"error_type":      string(errClientMissing),
			"tracing_id":      tracingID,
			"request_path":    "/auditlog/{name}",
			"token_id":        "",
			"token_subject":   "",
			"token_issuer":    "",
			"type":            "access_log",
			"pass_auth_check": "false",
			"project_id":      "unset-serviceinfo-Project",
			"service_type":    "unset-serviceinfo-Type",
			"service_name":    "unset-serviceinfo-Name",
		},
		HttpRequest: &hrpb.HttpRequest{
			RequestUrl:    "/auditlog/a",
			RequestMethod: http.MethodGet,
			RemoteIp:      "192.168.1.2",
			Status:        http.StatusUnauthorized,
		},
	}

	got := logs.Server.Logs[0].Entries[0]

	got.Timestamp = nil
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Fatalf("Logs returned diff (-want +got):\n%s", diff)
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

func setup(t *testing.T) (*mux.Router, *fakeoidcissuer.Server, *Checker, *handlerFuncStub, *fakesdl.Fake, func()) {
	t.Helper()

	oidc, err := fakeoidcissuer.New(issuerURL, &testkeys.PersonaBrokerKey, "dam-min", "testdata/config", false)
	if err != nil {
		t.Fatalf("fakeoidcissuer.New(%q, _, _, _, _) failed: %v", issuerURL, err)
	}

	store := storage.NewMemoryStorage("permissions", "testdata/config")

	logs, close := fakesdl.New()

	ctx := oidc.ContextWithClient(context.Background())
	verifier.NewPassportVerifier(ctx, issuerURL, test.TestClientID)

	c := NewChecker(logs.Client, issuerURL, permissions.New(store), clientSecrets, transformIdentity)

	stub := &handlerFuncStub{}

	r := mux.NewRouter()

	for k, v := range handlers {
		h, err := WithAuth(stub.handle, c, v)
		if err != nil {
			t.Fatalf("WithAuth(_, _, %v) failed for %s: %v", v, k, err)
		}
		r.HandleFunc(k, h)
	}

	return r, oidc, c, stub, logs, close
}

func sendRequest(method, path, clientID, clientSecret, token, tracingID, body string, handler http.Handler, oidc *fakeoidcissuer.Server) *http.Response {
	headers := make(map[string]string)
	if len(token) != 0 {
		headers["Authorization"] = "bearer " + token
	}
	if len(tracingID) != 0 {
		headers["X-Cloud-Trace-Context"] = tracingID
	}
	return sendRequestWithHeaders(method, path, clientID, clientSecret, body, headers, handler, oidc)
}

func sendRequestWithHeaders(method, path, clientID, clientSecret, body string, headers map[string]string, handler http.Handler, oidc *fakeoidcissuer.Server) *http.Response {
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

	for k, v := range headers {
		r.Header.Add(k, v)
	}

	r = r.WithContext(context.WithValue(r.Context(), oauth2.HTTPClient, oidc.Client()))
	r.RemoteAddr = "192.168.1.2:1234"

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

type handlerFuncStub struct {
	message string
}

func (s *handlerFuncStub) handle(w http.ResponseWriter, r *http.Request) {
	s.message = r.Method + " " + r.URL.Path
}

func errTypesFromLogs(s *fakesdl.Fake) []errType {
	s.Client.Close()
	var ets []errType
	for _, log := range s.Server.Logs {
		for _, e := range log.Entries {
			if et, ok := e.Labels["error_type"]; ok {
				ets = append(ets, errType(et))
			}
		}
	}
	return ets
}
