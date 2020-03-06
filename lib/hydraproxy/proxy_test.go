// Copyright 2020 Google LLC
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

package hydraproxy

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gorilla/mux" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/apis/hydraapi" /* copybara-comment: hydraapi */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakehydra" /* copybara-comment: fakehydra */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/httptestclient" /* copybara-comment: httptestclient */

	tpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/store/tokens" /* copybara-comment: go_proto */
)

func TestOAuthToken_code(t *testing.T) {
	s, f := setupOAuthTokenTest(t)

	wantCode := "code"
	sendExchangeToken(s, "code", wantCode, "")

	wantURL := "https://example.com/oauth2/token"
	if f.ExchangeTokenReqURL != wantURL {
		t.Errorf("ExchangeTokenReqURL in dest server = %s, want %s", f.ExchangeTokenReqURL, wantURL)
	}

	if f.ExchangeTokenReq.Get("code") != wantCode {
		t.Errorf("ExchangeTokenReq[code] = %s, want %s", f.ExchangeTokenReq.Get("code"), wantCode)
	}
}

func TestOAuthToken_refresh(t *testing.T) {
	s, f := setupOAuthTokenTest(t)

	wantRefreshToken := "reftok"
	sub := "sub"

	f.IntrospectionResp = &hydraapi.Introspection{
		Subject: sub,
		Extra:   map[string]interface{}{"tid": "token-id"},
	}

	sendExchangeToken(s, "refresh_token", "", wantRefreshToken)

	if f.IntrospectionReqToken != wantRefreshToken {
		t.Errorf("IntrospectionReqToken = %s, want %s", f.IntrospectionReqToken, wantRefreshToken)
	}

	wantURL := "https://example.com/oauth2/token"
	if f.ExchangeTokenReqURL != wantURL {
		t.Errorf("ExchangeTokenReqURL = %s, want %s", f.ExchangeTokenReqURL, wantURL)
	}

	if f.ExchangeTokenReq.Get("refresh_token") != wantRefreshToken {
		t.Errorf("ExchangeTokenReq[refresh_token] = %s, want %s", f.ExchangeTokenReq.Get("refresh_token"), wantRefreshToken)
	}
}

func TestOAuthToken_refresh_deleted(t *testing.T) {
	s, f := setupOAuthTokenTest(t)

	sub := "sub"
	tokenID := "token-id"
	f.IntrospectionResp = &hydraapi.Introspection{
		Subject: sub,
		Extra:   map[string]interface{}{"tid": tokenID},
	}

	pending := &tpb.PendingDeleteToken{}
	s.store.Write(storage.PendingDeleteTokenDatatype, storage.DefaultRealm, sub, tokenID, storage.LatestRev, pending, nil)

	wantRefreshToken := "reftok"
	resp := sendExchangeToken(s, "refresh_token", "", wantRefreshToken)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}

	if f.ExchangeTokenReq != nil {
		t.Errorf("ExchangeTokenReq = %v, want nil", f.ExchangeTokenReq)
	}

	if f.RevokeTokenReq != wantRefreshToken {
		t.Errorf("RevokeTokenReq = %s, want %s", f.RevokeTokenReq, wantRefreshToken)
	}

	if err := s.store.Read(storage.PendingDeleteTokenDatatype, storage.DefaultRealm, sub, tokenID, storage.LatestRev, pending); !storage.ErrNotFound(err) {
		t.Errorf("PendingDeleteToken should delete got value=%v err=%v", pending, err)
	}
}

func TestOAuthToken_refresh_error(t *testing.T) {
	s, f := setupOAuthTokenTest(t)

	tests := []struct {
		name          string
		introspectReq *hydraapi.Introspection
		introspectErr *hydraapi.GenericError
		wantStatus    int
	}{
		{
			name:          "no tid",
			introspectReq: &hydraapi.Introspection{},
			wantStatus:    http.StatusInternalServerError,
		},
		{
			name: "tid not string",
			introspectReq: &hydraapi.Introspection{
				Extra: map[string]interface{}{"tid": 1},
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "introspect err",
			introspectErr: &hydraapi.GenericError{
				Code: http.StatusUnauthorized,
			},
			// TODO: should convert hydra err to status err.
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f.Clear()
			f.IntrospectionResp = tc.introspectReq
			f.IntrospectionErr = tc.introspectErr

			resp := sendExchangeToken(s, "refresh_token", "code", "tok")

			if resp.StatusCode != tc.wantStatus {
				t.Errorf("StatusCode = %d, want %d", resp.StatusCode, tc.wantStatus)
			}

			if f.ExchangeTokenReq != nil {
				t.Errorf("ExchangeTokenReq = %v, want nil", f.ExchangeTokenReq)
			}
		})
	}
}

func TestOAuthToken_refresh_deleted_err(t *testing.T) {
	s, f := setupOAuthTokenTest(t)

	sub := "sub"
	tokenID := "token-id"
	f.IntrospectionResp = &hydraapi.Introspection{
		Subject: sub,
		Extra:   map[string]interface{}{"tid": tokenID},
	}
	f.RevokeTokenErr = &hydraapi.GenericError{
		Code: http.StatusUnauthorized,
	}

	pending := &tpb.PendingDeleteToken{}
	s.store.Write(storage.PendingDeleteTokenDatatype, storage.DefaultRealm, sub, tokenID, storage.LatestRev, pending, nil)

	resp := sendExchangeToken(s, "refresh_token", "", "tok")

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}

	if f.ExchangeTokenReq != nil {
		t.Errorf("ExchangeTokenReq = %v, want nil", f.ExchangeTokenReq)
	}

	if err := s.store.Read(storage.PendingDeleteTokenDatatype, storage.DefaultRealm, sub, tokenID, storage.LatestRev, pending); err != nil {
		t.Errorf("PendingDeleteToken should not delete")
	}
}

func sendExchangeToken(s *Service, grantType, code, refreshToken string) *http.Response {
	target := "https://example.com/oauth2/token"
	q := url.Values{}
	q.Set("grant_type", grantType)
	if len(code) > 0 {
		q.Set("code", code)
	}
	if len(refreshToken) > 0 {
		q.Set("refresh_token", refreshToken)
	}

	r := httptest.NewRequest(http.MethodPost, target, bytes.NewBufferString(q.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	s.HydraOAuthToken(w, r)

	return w.Result()
}

func setupOAuthTokenTest(t *testing.T) (*Service, *fakehydra.Server) {
	t.Helper()

	store := storage.NewMemoryStorage("ic-min", "testdata/config")

	router := mux.NewRouter()
	h := fakehydra.New(router)
	client := httptestclient.New(router)

	s, err := New(client, "http://hydra-admin.example.com", "http://hydra-pub-internal.example.com", store)
	if err != nil {
		t.Fatalf("New service failed: %v", err)
	}
	s.hydraPublicURLProxy.Transport = client.Transport

	return s, h
}
