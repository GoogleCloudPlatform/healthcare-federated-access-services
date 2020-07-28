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
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/auditlog" /* copybara-comment: auditlog */
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

	verifierErrParseFailed          = "token:parse_failed"
	verifierErrSubMissing           = "token:sub_missing"
	verifierErrIssuerNotMatch       = "token:issuer_not_match"
	verifierErrInvalidSignature     = "token:invalid_signature"
	verifierErrInvalidAudience      = "token:invalid_aud"
	verifierErrExpired              = "token:expired"
	verifierErrFutureToken          = "token:future_token"
	verifierErrUserinfoInvalidToken = "token:userinfo_invalid_token"
)

var (
	handlers = map[string]Require{
		"/norequirement":    RequireNone,
		"/clientidonly":     RequireClientID,
		"/clientsecret":     RequireClientIDAndSecret,
		"/usertoken":        RequireUserTokenClientCredential,
		"/usertoken/{user}": RequireUserTokenClientCredential,
		"/admintoken":       RequireAdminTokenClientCredential,
		"/auditlog/{name}":  RequireUserTokenClientCredential,
		"/acctadmin/{name}": RequireAccountAdminUserTokenCredential,
	}
)

func Test_LargeBody(t *testing.T) {
	testUseJWTAndUserinfo(t, func(t *testing.T, param *testParam) {
		router, oidc, _, _, _ := setup(t, param)

		// Build a big http body
		sb := strings.Builder{}
		for i := 0; i < maxHTTPBody+10; i++ {
			sb.WriteString("a")
		}

		resp := sendRequest(http.MethodPost, "/norequirement", "", "", "", "", sb.String(), router, oidc)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("unexpected status code: %d wants %d", resp.StatusCode, http.StatusBadRequest)
		}
	})
}

func Test_LargeBody_Log(t *testing.T) {
	testUseJWTAndUserinfo(t, func(t *testing.T, param *testParam) {

		router, oidc, _, _, logs := setup(t, param)
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
	})
}

func Test_ErrorAtClientSecret(t *testing.T) {
	testUseJWTAndUserinfo(t, func(t *testing.T, param *testParam) {
		for path, require := range handlers {
			t.Run(path, func(t *testing.T) {
				router, oidc, service, _, _ := setup(t, param)

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
	})
}

func Test_ErrorAtClientSecret_Log(t *testing.T) {
	testUseJWTAndUserinfo(t, func(t *testing.T, param *testParam) {
		for path, require := range handlers {
			t.Run(path, func(t *testing.T) {
				router, oidc, service, _, logs := setup(t, param)

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
	})
}

func Test_RequiresClientID(t *testing.T) {
	testUseJWTAndUserinfo(t, func(t *testing.T, param *testParam) {
		router, oidc, _, stub, _ := setup(t, param)

		resp := sendRequest(http.MethodGet, "/clientidonly", test.TestClientID, "", "", "", "", router, oidc)
		want := "GET /clientidonly"
		if stub.message != want {
			t.Errorf("stub.message=%q wants %q", stub.message, want)
		}

		if resp.StatusCode != http.StatusOK {
			t.Errorf("unexpected status code: %d wants %d", resp.StatusCode, http.StatusOK)
		}
	})
}

func Test_RequiresClientID_Log(t *testing.T) {
	testUseJWTAndUserinfo(t, func(t *testing.T, param *testParam) {
		router, oidc, _, _, logs := setup(t, param)

		sendRequest(http.MethodGet, "/clientidonly", test.TestClientID, "", "", "", "", router, oidc)

		ets := errTypesFromLogs(logs)
		wantErrType := []errType{""}
		if diff := cmp.Diff(wantErrType, ets); len(diff) != 0 {
			t.Errorf("error_type (-want +got): %s", diff)
		}
	})
}

func Test_RequiresClientID_Error(t *testing.T) {
	testUseJWTAndUserinfo(t, func(t *testing.T, param *testParam) {
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
				router, oidc, _, _, _ := setup(t, param)

				resp := sendRequest(http.MethodGet, "/clientidonly", tc.clientID, "", "", "", "", router, oidc)
				if resp.StatusCode != http.StatusUnauthorized {
					t.Errorf("unexpected status code: %d want %d", resp.StatusCode, http.StatusUnauthorized)
				}
			})
		}
	})
}

func Test_RequiresClientID_Error_Log(t *testing.T) {
	testUseJWTAndUserinfo(t, func(t *testing.T, param *testParam) {
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
				router, oidc, _, _, logs := setup(t, param)

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
	})
}

func Test_RequiresClientSecret(t *testing.T) {
	testUseJWTAndUserinfo(t, func(t *testing.T, param *testParam) {
		router, oidc, _, stub, _ := setup(t, param)

		resp := sendRequest(http.MethodGet, "/clientsecret", test.TestClientID, test.TestClientSecret, "", "", "", router, oidc)
		want := "GET /clientsecret"
		if stub.message != want {
			t.Errorf("stub.message=%q wants %q", stub.message, want)
		}

		if resp.StatusCode != http.StatusOK {
			t.Errorf("unexpected status code: %d wants %d", resp.StatusCode, http.StatusOK)
		}
	})
}

func Test_RequiresClientSecret_Log(t *testing.T) {
	testUseJWTAndUserinfo(t, func(t *testing.T, param *testParam) {
		router, oidc, _, _, logs := setup(t, param)

		sendRequest(http.MethodGet, "/clientsecret", test.TestClientID, test.TestClientSecret, "", "", "", router, oidc)

		ets := errTypesFromLogs(logs)
		wantErrType := []errType{""}
		if diff := cmp.Diff(wantErrType, ets); len(diff) != 0 {
			t.Errorf("error_type (-want +got): %s", diff)
		}
	})
}

func Test_RequiresClientSecret_Error(t *testing.T) {
	testUseJWTAndUserinfo(t, func(t *testing.T, param *testParam) {
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
				router, oidc, _, _, _ := setup(t, param)

				resp := sendRequest(http.MethodGet, "/clientsecret", test.TestClientID, tc.clientSecret, "", "", "", router, oidc)
				if resp.StatusCode != http.StatusUnauthorized {
					t.Errorf("unexpected status code: %d want %d", resp.StatusCode, http.StatusUnauthorized)
				}
			})
		}
	})
}

func Test_RequiresClientSecret_Error_Log(t *testing.T) {
	testUseJWTAndUserinfo(t, func(t *testing.T, param *testParam) {
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
				router, oidc, _, _, logs := setup(t, param)

				sendRequest(http.MethodGet, "/clientsecret", test.TestClientID, tc.clientSecret, "", "", "", router, oidc)

				ets := errTypesFromLogs(logs)
				wantErrType := []errType{errSecretMismatch}
				if diff := cmp.Diff(wantErrType, ets); len(diff) != 0 {
					t.Errorf("error_type (-want +got): %s", diff)
				}
			})
		}
	})
}

func Test_RequiresToken_Error(t *testing.T) {
	testUseJWTAndUserinfo(t, func(t *testing.T, param *testParam) {
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
					router, oidc, _, _, _ := setup(t, param)

					resp := sendRequest(http.MethodGet, p, test.TestClientID, test.TestClientSecret, tc.tok, "", "", router, oidc)
					if resp.StatusCode != http.StatusUnauthorized {
						t.Errorf("unexpected status code: %d want %d", resp.StatusCode, http.StatusUnauthorized)
					}
				})
			}
		}
	})
}

func Test_RequiresToken_Error_Log(t *testing.T) {
	testUseJWTAndUserinfo(t, func(t *testing.T, param *testParam) {
		notJWTErr := verifierErrParseFailed
		if param.useUserinfo {
			notJWTErr = verifierErrUserinfoInvalidToken
		}
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
				et:   notJWTErr,
			},
		}

		paths := []string{"/usertoken", "/usertoken/sub", "/admintoken"}

		for _, tc := range tests {
			for _, p := range paths {
				t.Run(tc.name+" "+p, func(t *testing.T) {
					router, oidc, _, _, logs := setup(t, param)

					sendRequest(http.MethodGet, p, test.TestClientID, test.TestClientSecret, tc.tok, "", "", router, oidc)

					ets := errTypesFromLogs(logs)
					wantErrType := []errType{tc.et}
					if diff := cmp.Diff(wantErrType, ets); len(diff) != 0 {
						t.Errorf("error_type (-want +got): %s", diff)
					}
				})
			}
		}
	})
}

func Test_RequiresToken_JWT_Invalid_Signature(t *testing.T) {
	testUseJWTAndUserinfo(t, func(t *testing.T, param *testParam) {
		now := time.Now().Unix()
		claims := &ga4gh.Identity{
			Issuer:    issuerURL,
			Subject:   "non-admin",
			IssuedAt:  now,
			Expiry:    now + 10000,
			Audiences: ga4gh.NewAudience(test.TestClientID),
		}

		paths := []string{"/usertoken", "/usertoken/sub", "/admintoken"}

		for _, p := range paths {
			t.Run(p, func(t *testing.T) {
				router, oidc, _, _, _ := setup(t, param)

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
	})
}

func Test_RequiresToken_JWT_Invalid_Signature_Log(t *testing.T) {
	testUseJWTAndUserinfo(t, func(t *testing.T, param *testParam) {
		now := time.Now().Unix()
		claims := &ga4gh.Identity{
			Issuer:    issuerURL,
			Subject:   "non-admin",
			IssuedAt:  now,
			Expiry:    now + 10000,
			Audiences: ga4gh.NewAudience(test.TestClientID),
		}

		paths := []string{"/usertoken", "/usertoken/sub", "/admintoken"}

		for _, p := range paths {
			t.Run(p, func(t *testing.T) {
				router, oidc, _, _, logs := setup(t, param)

				tok, err := oidc.Sign(nil, claims)
				if err != nil {
					t.Fatalf("oidc.Sign() failed: %v", err)
				}

				tok = tok + "invalid"

				sendRequest(http.MethodGet, p, test.TestClientID, test.TestClientSecret, tok, "", "", router, oidc)

				ets := errTypesFromLogs(logs)
				wantErrType := []errType{verifierErrInvalidSignature}
				if param.useUserinfo {
					wantErrType = []errType{verifierErrUserinfoInvalidToken}
				}
				if diff := cmp.Diff(wantErrType, ets); len(diff) != 0 {
					t.Errorf("error_type (-want +got): %s", diff)
				}
			})
		}
	})
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
				Subject:   "non-admin",
				IssuedAt:  now - 100000,
				Expiry:    now - 10000,
				Audiences: ga4gh.NewAudience(test.TestClientID),
			},
		},
		{
			name: "future token",
			claims: &ga4gh.Identity{
				Issuer:    issuerURL,
				Subject:   "non-admin",
				IssuedAt:  now + 10000,
				Expiry:    now + 100000,
				Audiences: ga4gh.NewAudience(test.TestClientID),
			},
		},
		{
			name: "clientID in token not match in request",
			claims: &ga4gh.Identity{
				Issuer:    issuerURL,
				Subject:   "non-admin",
				IssuedAt:  now,
				Expiry:    now + 10000,
				Audiences: ga4gh.NewAudience("invalid"),
			},
		},
		{
			name: "issuer not match",
			claims: &ga4gh.Identity{
				Issuer:    issuerURL + "invalid/",
				Subject:   "non-admin",
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
				router, oidc, _, _, _ := setup(t, &testParam{})

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
				Subject:   "non-admin",
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
				Subject:   "non-admin",
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
				Subject:   "non-admin",
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
				Subject:   "non-admin",
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
				router, oidc, _, _, logs := setup(t, &testParam{})

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
	testUseJWTAndUserinfo(t, func(t *testing.T, param *testParam) {
		now := time.Now().Unix()
		claims := &ga4gh.Identity{
			Issuer:    issuerURL,
			Subject:   "non-admin",
			IssuedAt:  now,
			Expiry:    now + 10000,
			Audiences: ga4gh.NewAudience(test.TestClientID),
		}

		paths := []string{"/usertoken", "/usertoken/non-admin"}

		for _, p := range paths {
			t.Run(p, func(t *testing.T) {
				router, oidc, _, stub, _ := setup(t, param)

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
	})
}

func Test_RequiresUserToken_Log(t *testing.T) {
	testUseJWTAndUserinfo(t, func(t *testing.T, param *testParam) {
		now := time.Now().Unix()
		claims := &ga4gh.Identity{
			Issuer:    issuerURL,
			Subject:   "non-admin",
			IssuedAt:  now,
			Expiry:    now + 10000,
			Audiences: ga4gh.NewAudience(test.TestClientID),
		}

		paths := []string{"/usertoken", "/usertoken/non-admin"}

		for _, p := range paths {
			t.Run(p, func(t *testing.T) {
				router, oidc, _, _, logs := setup(t, param)

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
	})
}

func Test_RequiresUserToken_UserMisatch(t *testing.T) {
	testUseJWTAndUserinfo(t, func(t *testing.T, param *testParam) {
		router, oidc, _, _, _ := setup(t, param)

		now := time.Now().Unix()
		claims := &ga4gh.Identity{
			Issuer:    issuerURL,
			Subject:   "non-admin",
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
	})
}

func Test_RequiresUserToken_UserMismatch_Log(t *testing.T) {
	testUseJWTAndUserinfo(t, func(t *testing.T, param *testParam) {
		router, oidc, _, _, logs := setup(t, param)

		now := time.Now().Unix()
		claims := &ga4gh.Identity{
			Issuer:    issuerURL,
			Subject:   "non-admin",
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
	})
}

func Test_RequiresAdminToken(t *testing.T) {
	testUseJWTAndUserinfo(t, func(t *testing.T, param *testParam) {
		router, oidc, _, stub, _ := setup(t, param)

		now := time.Now().Unix()
		claims := &ga4gh.Identity{
			Issuer:    issuerURL,
			Subject:   "admin",
			IssuedAt:  now,
			Expiry:    now + 10000,
			Audiences: ga4gh.NewAudience(test.TestClientID),
			Identities: map[string][]string{
				"admin@example.com": nil,
			},
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
	})
}

func Test_RequiresAdminToken_Log(t *testing.T) {
	testUseJWTAndUserinfo(t, func(t *testing.T, param *testParam) {
		router, oidc, _, _, logs := setup(t, param)

		now := time.Now().Unix()
		claims := &ga4gh.Identity{
			Issuer:    issuerURL,
			Subject:   "admin",
			IssuedAt:  now,
			Expiry:    now + 10000,
			Audiences: ga4gh.NewAudience(test.TestClientID),
			Identities: map[string][]string{
				"admin@example.com": nil,
			},
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
	})
}

func Test_RequiresAdminToken_Error(t *testing.T) {
	testUseJWTAndUserinfo(t, func(t *testing.T, param *testParam) {
		router, oidc, _, _, _ := setup(t, param)

		now := time.Now().Unix()
		claims := &ga4gh.Identity{
			Issuer:    issuerURL,
			Subject:   "non-admin",
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
	})
}

func Test_RequiresAdminToken_Error_Log(t *testing.T) {
	testUseJWTAndUserinfo(t, func(t *testing.T, param *testParam) {
		router, oidc, _, _, logs := setup(t, param)

		now := time.Now().Unix()
		claims := &ga4gh.Identity{
			Issuer:    issuerURL,
			Subject:   "non-admin",
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
	})
}

func Test_RequiresAccountAdminUserToken(t *testing.T) {
	testUseJWTAndUserinfo(t, func(t *testing.T, param *testParam) {
		now := time.Now().Unix()
		claims := &ga4gh.Identity{
			Issuer:    issuerURL,
			Subject:   "non-admin",
			Scope:     "openid account_admin offline",
			IssuedAt:  now,
			Expiry:    now + 10000,
			Audiences: ga4gh.NewAudience(test.TestClientID),
		}

		router, oidc, _, stub, _ := setup(t, param)

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
	})
}

func Test_RequiresAccountAdminUserToken_Log(t *testing.T) {
	testUseJWTAndUserinfo(t, func(t *testing.T, param *testParam) {
		now := time.Now().Unix()
		claims := &ga4gh.Identity{
			Issuer:    issuerURL,
			Subject:   "non-admin",
			Scope:     "openid account_admin offline",
			IssuedAt:  now,
			Expiry:    now + 10000,
			Audiences: ga4gh.NewAudience(test.TestClientID),
		}

		router, oidc, _, _, logs := setup(t, param)

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
	})
}

func Test_RequiresAccountAdminUserToken_Error(t *testing.T) {
	testUseJWTAndUserinfo(t, func(t *testing.T, param *testParam) {
		now := time.Now().Unix()
		claims := &ga4gh.Identity{
			Issuer:    issuerURL,
			Subject:   "non-admin",
			Scope:     "openid offline",
			IssuedAt:  now,
			Expiry:    now + 10000,
			Audiences: ga4gh.NewAudience(test.TestClientID),
		}

		router, oidc, _, _, _ := setup(t, param)

		tok, err := oidc.Sign(nil, claims)
		if err != nil {
			t.Fatalf("oidc.Sign() failed: %v", err)
		}

		resp := sendRequest(http.MethodPost, "/acctadmin/sub", test.TestClientID, test.TestClientSecret, tok, "", "", router, oidc)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("unexpected status code: %d want %d", resp.StatusCode, http.StatusUnauthorized)
		}
	})
}

func Test_RequiresAccountAdminUserToken_Error_Log(t *testing.T) {
	testUseJWTAndUserinfo(t, func(t *testing.T, param *testParam) {
		now := time.Now().Unix()
		claims := &ga4gh.Identity{
			Issuer:    issuerURL,
			Subject:   "non-admin",
			Scope:     "openid offline",
			IssuedAt:  now,
			Expiry:    now + 10000,
			Audiences: ga4gh.NewAudience(test.TestClientID),
		}

		router, oidc, _, _, logs := setup(t, param)

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
	})
}

func Test_UserAndLinkToken(t *testing.T) {
	testUseJWTAndUserinfo(t, func(t *testing.T, param *testParam) {
		now := time.Now().Unix()
		claims := &ga4gh.Identity{
			Issuer:    issuerURL,
			Subject:   "non-admin",
			Scope:     "openid offline link",
			IssuedAt:  now,
			Expiry:    now + 10000,
			Audiences: ga4gh.NewAudience(test.TestClientID),
		}

		router, oidc, _, stub, _ := setup(t, param)

		tok, err := oidc.Sign(nil, claims)
		if err != nil {
			t.Fatalf("oidc.Sign() failed: %v", err)
		}

		headers := map[string]string{
			"Authorization":        "bearer " + tok,
			"X-Link-Authorization": "bearer " + tok,
		}

		path := "/usertoken/non-admin"
		resp := sendRequestWithHeaders(http.MethodPost, path, test.TestClientID, test.TestClientSecret, "", headers, router, oidc)
		want := "POST " + path
		if stub.message != want {
			t.Errorf("stub.message=%q wants %q", stub.message, want)
		}

		if resp.StatusCode != http.StatusOK {
			t.Errorf("unexpected status code: %d wants %d", resp.StatusCode, http.StatusOK)
		}
	})
}

func Test_UserAndLinkToken_Error(t *testing.T) {
	testUseJWTAndUserinfo(t, func(t *testing.T, param *testParam) {
		now := time.Now().Unix()
		claims := &ga4gh.Identity{
			Issuer:    issuerURL,
			Subject:   "non-admin",
			Scope:     "openid offline",
			IssuedAt:  now,
			Expiry:    now + 10000,
			Audiences: ga4gh.NewAudience(test.TestClientID),
		}

		router, oidc, _, _, _ := setup(t, param)

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
	})
}

func Test_UserAndLinkToken_Error_Log(t *testing.T) {
	testUseJWTAndUserinfo(t, func(t *testing.T, param *testParam) {
		now := time.Now().Unix()
		claims := &ga4gh.Identity{
			Issuer:    issuerURL,
			Subject:   "non-admin",
			Scope:     "openid offline",
			IssuedAt:  now,
			Expiry:    now + 10000,
			Audiences: ga4gh.NewAudience(test.TestClientID),
		}

		router, oidc, _, _, logs := setup(t, param)

		tok, err := oidc.Sign(nil, claims)
		if err != nil {
			t.Fatalf("oidc.Sign() failed: %v", err)
		}

		headers := map[string]string{
			"Authorization":        "bearer " + tok,
			"X-Link-Authorization": "bearer " + tok,
		}

		sendRequestWithHeaders(http.MethodPost, "/usertoken/non-admin", test.TestClientID, test.TestClientSecret, "", headers, router, oidc)

		ets := errTypesFromLogs(logs)
		wantErrType := []errType{errScopeMissing}
		if diff := cmp.Diff(wantErrType, ets); len(diff) != 0 {
			t.Errorf("error_type (-want +got): %s", diff)
		}
	})
}

func Test_writeRequestLog_auth_pass(t *testing.T) {
	testUseJWTAndUserinfo(t, func(t *testing.T, param *testParam) {
		now := time.Now().Unix()

		tests := []struct {
			name   string
			claims *ga4gh.Identity
		}{
			{
				name: "tid in extra",
				claims: &ga4gh.Identity{
					Issuer:    issuerURL,
					Subject:   "non-admin",
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
					Subject:   "non-admin",
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
					Subject:   "non-admin",
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

				router, oidc, _, _, logs := setup(t, param)

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
						"error_type":       "",
						"tracing_id":       tracingID,
						"request_endpoint": "/auditlog/{name}",
						"request_path":     "/auditlog/a",
						"token_id":         "id",
						"token_subject":    "non-admin",
						"token_issuer":     normalize(issuerURL),
						"type":             auditlog.TypeRequestLog,
						"pass_auth_check":  "true",
						"project_id":       "unset-serviceinfo-Project",
						"service_type":     "unset-serviceinfo-Type",
						"service_name":     "unset-serviceinfo-Name",
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
	})
}

func Test_writeRequestLog_auth_failed(t *testing.T) {
	testUseJWTAndUserinfo(t, func(t *testing.T, param *testParam) {
		router, oidc, _, _, logs := setup(t, param)

		tracingID := "1"
		sendRequest(http.MethodGet, "/auditlog/a", "", "", "", tracingID, "", router, oidc)
		logs.Client.Close()

		want := &lepb.LogEntry{
			Payload:  &lepb.LogEntry_TextPayload{TextPayload: "rpc error: code = Unauthenticated desc = requires a valid client ID"},
			Severity: lspb.LogSeverity_DEFAULT,
			Labels: map[string]string{
				"error_type":       string(errClientMissing),
				"tracing_id":       tracingID,
				"request_endpoint": "/auditlog/{name}",
				"request_path":     "/auditlog/a",
				"token_id":         "",
				"token_subject":    "",
				"token_issuer":     "",
				"type":             auditlog.TypeRequestLog,
				"pass_auth_check":  "false",
				"project_id":       "unset-serviceinfo-Project",
				"service_type":     "unset-serviceinfo-Type",
				"service_name":     "unset-serviceinfo-Name",
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
	})
}

func TestUserTokenOnly(t *testing.T) {
	testUseJWTAndUserinfo(t, func(t *testing.T, param *testParam) {
		router, oidc, c, stub, _ := setup(t, param)

		p := "/usertokenonly"
		require := Require{Role: User, SelfClientID: test.TestClientID}
		h, err := WithAuth(stub.handle, c, require)
		if err != nil {
			t.Fatalf("WithAuth(_, _, %v) failed for %s: %v", require, p, err)
		}

		router.HandleFunc(p, h)

		now := time.Now().Unix()
		claims := &ga4gh.Identity{
			Issuer:    issuerURL,
			Subject:   "non-admin",
			Scope:     "openid offline",
			IssuedAt:  now,
			Expiry:    now + 10000,
			Audiences: ga4gh.NewAudience(test.TestClientID),
		}

		tok, err := oidc.Sign(nil, claims)
		if err != nil {
			t.Fatalf("oidc.Sign() failed: %v", err)
		}

		resp := sendRequest(http.MethodGet, "/usertokenonly", "", "", tok, "", "", router, oidc)

		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, wants %d", resp.StatusCode, http.StatusOK)
		}
	})
}

func TestUserTokenOnly_Err(t *testing.T) {
	router, oidc, c, stub, _ := setup(t, &testParam{})

	p := "/usertokenonly"
	require := Require{Role: User, SelfClientID: test.TestClientID}
	h, err := WithAuth(stub.handle, c, require)
	if err != nil {
		t.Fatalf("WithAuth(_, _, %v) failed for %s: %v", require, p, err)
	}

	router.HandleFunc(p, h)

	now := time.Now().Unix()

	tests := []struct {
		name   string
		claims *ga4gh.Identity
		status int
	}{
		{
			name: "iss not match",
			claims: &ga4gh.Identity{
				Issuer:    "https://invalid.com",
				Subject:   "non-admin",
				Scope:     "openid offline",
				IssuedAt:  now,
				Expiry:    now + 10000,
				Audiences: ga4gh.NewAudience(test.TestClientID),
			},
			status: http.StatusUnauthorized,
		},
		{
			name: "aud not match",
			claims: &ga4gh.Identity{
				Issuer:    issuerURL,
				Subject:   "non-admin",
				Scope:     "openid offline",
				IssuedAt:  now,
				Expiry:    now + 10000,
				Audiences: ga4gh.NewAudience(issuerURL),
			},
			status: http.StatusUnauthorized,
		},
		{
			name: "use azp not match",
			claims: &ga4gh.Identity{
				Issuer:          issuerURL,
				Subject:         "sub",
				Scope:           "openid offline",
				IssuedAt:        now,
				Expiry:          now + 10000,
				AuthorizedParty: test.TestClientID,
			},
			status: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := oidc.Sign(nil, tc.claims)
			if err != nil {
				t.Fatalf("oidc.Sign() failed: %v", err)
			}

			resp := sendRequest(http.MethodGet, "/usertokenonly", "", "", tok, "", "", router, oidc)

			if resp.StatusCode != tc.status {
				t.Errorf("status = %d, wants %d", resp.StatusCode, tc.status)
			}
		})
	}
}

func TestAllowIssuerOnAudAzp_AllowAzp(t *testing.T) {
	router, oidc, c, stub, _ := setup(t, &testParam{})

	paths := map[string]Require{
		"/false/false": {Role: User, SelfClientID: test.TestClientID},
		"/false/true":  {Role: User, SelfClientID: test.TestClientID, AllowAzp: true},
		"/true/false":  {Role: User, SelfClientID: test.TestClientID, AllowIssuerInAudOrAzp: true},
		"/true/true":   {Role: User, SelfClientID: test.TestClientID, AllowIssuerInAudOrAzp: true, AllowAzp: true},
	}

	for k, v := range paths {
		h, err := WithAuth(stub.handle, c, v)
		if err != nil {
			t.Fatalf("WithAuth(_, _, %v) failed for %s: %v", v, k, err)
		}
		router.HandleFunc(k, h)
	}

	tests := []struct {
		name string
		path string
		aud  string
		azp  string
		want int
	}{
		{
			name: "not allow issuer not allow azp, aud = empty, azp = empty",
			path: "/false/false",
			want: http.StatusUnauthorized,
		},
		{
			name: "not allow issuer not allow azp, aud = clientid, azp = empty",
			path: "/false/false",
			aud:  test.TestClientID,
			want: http.StatusOK,
		},
		{
			name: "not allow issuer not allow azp, aud = empty, azp = clientid",
			path: "/false/false",
			azp:  test.TestClientID,
			want: http.StatusUnauthorized,
		},
		{
			name: "not allow issuer not allow azp, aud = issuer, azp = empty",
			path: "/false/false",
			aud:  issuerURL,
			want: http.StatusUnauthorized,
		},
		{
			name: "not allow issuer not allow azp, aud = empty, azp = issuer",
			path: "/false/false",
			azp:  issuerURL,
			want: http.StatusUnauthorized,
		},
		{
			name: "allow issuer not allow azp, aud = empty, azp = empty",
			path: "/true/false",
			want: http.StatusUnauthorized,
		},
		{
			name: "allow issuer not allow azp, aud = clientid, azp = empty",
			path: "/true/false",
			aud:  test.TestClientID,
			want: http.StatusOK,
		},
		{
			name: "allow issuer not allow azp, aud = empty, azp = clientid",
			path: "/true/false",
			azp:  test.TestClientID,
			want: http.StatusUnauthorized,
		},
		{
			name: "allow issuer not allow azp, aud = issuer, azp = empty",
			path: "/true/false",
			aud:  issuerURL,
			want: http.StatusOK,
		},
		{
			name: "allow issuer not allow azp, aud = empty, azp = issuer",
			path: "/true/false",
			azp:  issuerURL,
			want: http.StatusUnauthorized,
		},
		{
			name: "not allow issuer allow azp, aud = empty, azp = empty",
			path: "/false/true",
			want: http.StatusUnauthorized,
		},
		{
			name: "not allow issuer allow azp, aud = clientid, azp = empty",
			path: "/false/true",
			aud:  test.TestClientID,
			want: http.StatusOK,
		},
		{
			name: "not allow issuer allow azp, aud = empty, azp = clientid",
			path: "/false/true",
			azp:  test.TestClientID,
			want: http.StatusOK,
		},
		{
			name: "not allow issuer allow azp, aud = issuer, azp = empty",
			path: "/false/true",
			aud:  issuerURL,
			want: http.StatusUnauthorized,
		},
		{
			name: "not allow issuer allow azp, aud = empty, azp = issuer",
			path: "/false/true",
			azp:  issuerURL,
			want: http.StatusUnauthorized,
		},
		{
			name: "allow issuer allow azp, aud = empty, azp = empty",
			path: "/true/true",
			want: http.StatusUnauthorized,
		},
		{
			name: "allow issuer allow azp, aud = clientid, azp = empty",
			path: "/true/true",
			aud:  test.TestClientID,
			want: http.StatusOK,
		},
		{
			name: "allow issuer allow azp, aud = empty, azp = clientid",
			path: "/true/true",
			azp:  test.TestClientID,
			want: http.StatusOK,
		},
		{
			name: "allow issuer allow azp, aud = issuer, azp = empty",
			path: "/true/true",
			aud:  issuerURL,
			want: http.StatusOK,
		},
		{
			name: "allow issuer allow azp, aud = empty, azp = issuer",
			path: "/true/true",
			azp:  issuerURL,
			want: http.StatusOK,
		},
	}

	now := time.Now().Unix()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := &ga4gh.Identity{
				Issuer:          issuerURL,
				Subject:         "sub",
				Scope:           "openid offline",
				IssuedAt:        now,
				Expiry:          now + 10000,
				Audiences:       []string{tc.aud},
				AuthorizedParty: tc.azp,
			}

			tok, err := oidc.Sign(nil, claims)
			if err != nil {
				t.Fatalf("oidc.Sign() failed: %v", err)
			}

			resp := sendRequest(http.MethodGet, tc.path, "", "", tok, "", "", router, oidc)

			if resp.StatusCode != tc.want {
				t.Errorf("status = %d, wants %d", resp.StatusCode, tc.want)
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

type testParam struct {
	useUserinfo bool
}

func testUseJWTAndUserinfo(t *testing.T, f func(t *testing.T, params *testParam)) {
	tests := []struct {
		name  string
		param *testParam
	}{
		{
			name:  "jwt_access_token",
			param: &testParam{useUserinfo: false},
		},
		{
			name:  "user_userinfo",
			param: &testParam{useUserinfo: true},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f(t, tc.param)
		})
	}
}

func setup(t *testing.T, param *testParam) (*mux.Router, *fakeoidcissuer.Server, *Checker, *handlerFuncStub, *fakesdl.Fake) {
	t.Helper()

	oidc, err := fakeoidcissuer.New(issuerURL, &testkeys.PersonaBrokerKey, "dam-min", "testdata/config", false)
	if err != nil {
		t.Fatalf("fakeoidcissuer.New(%q, _, _, _, _) failed: %v", issuerURL, err)
	}

	store := storage.NewMemoryStorage("permissions", "testdata/config")

	logs, close := fakesdl.New()
	t.Cleanup(close)

	ctx := oidc.ContextWithClient(context.Background())
	verifier.NewPassportVerifier(ctx, issuerURL, test.TestClientID)

	c := NewChecker(logs.Client, issuerURL, permissions.New(store), clientSecrets, transformIdentity, param.useUserinfo)

	stub := &handlerFuncStub{}

	r := mux.NewRouter()

	for k, v := range handlers {
		h, err := WithAuth(stub.handle, c, v)
		if err != nil {
			t.Fatalf("WithAuth(_, _, %v) failed for %s: %v", v, k, err)
		}
		r.HandleFunc(k, h)
	}

	return r, oidc, c, stub, logs
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
