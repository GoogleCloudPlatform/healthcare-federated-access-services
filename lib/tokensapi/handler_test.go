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

package tokensapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"github.com/gorilla/mux" /* copybara-comment */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/handlerfactory" /* copybara-comment: handlerfactory */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	tpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/tokens/v1" /* copybara-comment: go_proto */
)

var (
	tokensPath = "/dam/v1alpha/users/{user}/tokens"
	tokenPath  = "/dam/v1alpha/users/{user}/tokens/{token_id}"
)

func Test_TokenNameCodec(t *testing.T) {
	prefix := "gcp"
	tokenID := "1234"
	encoded := encodeTokenName("u1", prefix, tokenID)
	wantEncoded := "users/u1/tokens/gcp:MTIzNA"
	if encoded != wantEncoded {
		t.Errorf("encodeTokenName(user, gcp, 1234) = %s, wants %s", encoded, wantEncoded)
	}

	pre, tID, err := decodeTokenName("gcp:MTIzNA")
	if err != nil {
		t.Fatalf("decodeTokenName(gcp:MTIzNA) failed: %v", err)
	}

	if pre != prefix {
		t.Errorf("prefix = %s, wants %s", pre, prefix)
	}
	if tID != tokenID {
		t.Errorf("tokenID = %s, wants %s", tID, tokenID)
	}
}

func TestListTokens(t *testing.T) {
	stub := &stubTokenProvider{
		listResp: []*Token{
			{
				User:        "u-0001",
				TokenPrefix: "gcp",
				RawTokenID:  "t-0001",
				IssuedAt:    0,
				ExpiresAt:   100,
			},
			{
				User:        "u-0001",
				TokenPrefix: "gcp",
				RawTokenID:  "t-0002",
				IssuedAt:    0,
				ExpiresAt:   100,
			},
		},
	}

	h := setup([]TokenProvider{stub})

	u := "http://example.com/dam/v1alpha/users/test/tokens"
	r := httptest.NewRequest(http.MethodGet, u, nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, wants %d", resp.StatusCode, http.StatusOK)
	}

	got := &tpb.ListTokensResponse{}
	httputils.MustDecodeJSONPBResp(t, resp, got)
	want := &tpb.ListTokensResponse{
		Tokens: []*tpb.Token{
			{
				Name:      encodeTokenName("u-0001", "gcp", "t-0001"),
				IssuedAt:  0,
				ExpiresAt: 100,
			},
			{
				Name:      encodeTokenName("u-0001", "gcp", "t-0002"),
				IssuedAt:  0,
				ExpiresAt: 100,
			},
		},
	}

	if d := cmp.Diff(want, got, protocmp.Transform()); len(d) > 0 {
		t.Errorf("listToken (-want, +got): %s", d)
	}
}

func TestListTokens_ErrorFromTokenProvider(t *testing.T) {
	stub := &stubTokenProvider{
		listErr: status.Errorf(codes.NotFound, "not found"),
	}

	h := setup([]TokenProvider{stub})

	u := "http://example.com/dam/v1alpha/users/test/tokens"
	r := httptest.NewRequest(http.MethodGet, u, nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	resp := w.Result()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("StatusCode = %d, wants %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestDeleteToken(t *testing.T) {
	stub := &stubTokenProvider{}
	h := setup([]TokenProvider{stub})
	u := "http://example.com/dam/v1alpha/users/test/tokens/gcp:MTIzNA"
	r := httptest.NewRequest(http.MethodDelete, u, nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, wants %d", resp.StatusCode, http.StatusOK)
	}

	user := "test"
	tokenID := "1234"
	if stub.deleteReqUser != user {
		t.Errorf("deleteReqUser = %s, wants %s", stub.deleteReqUser, user)
	}
	if stub.deleteReqTokenID != tokenID {
		t.Errorf("deleteReqTokenID = %s, wants %s", stub.deleteReqTokenID, tokenID)
	}
}

func TestDeleteToken_Error(t *testing.T) {
	tests := []struct {
		name      string
		tokenID   string
		providers []TokenProvider
		status    int
	}{
		{
			name:      "prefix not allow",
			tokenID:   "invalid:MTIzNA",
			providers: []TokenProvider{&stubTokenProvider{}},
			status:    http.StatusBadRequest,
		},
		{
			name:      "no prefix",
			tokenID:   "invalid",
			providers: []TokenProvider{&stubTokenProvider{}},
			status:    http.StatusBadRequest,
		},
		{
			name:      "provider not found",
			tokenID:   "gcp:MTIzNA",
			providers: []TokenProvider{},
			status:    http.StatusBadRequest,
		},
		{
			name:    "provider error",
			tokenID: "gcp:MTIzNA",
			providers: []TokenProvider{
				&stubTokenProvider{
					deleteErr: status.Errorf(codes.NotFound, "not found"),
				},
			},
			status: http.StatusNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := setup(tc.providers)
			u := "http://example.com/dam/v1alpha/users/test/tokens/" + tc.tokenID
			r := httptest.NewRequest(http.MethodDelete, u, nil)
			w := httptest.NewRecorder()

			h.ServeHTTP(w, r)

			resp := w.Result()
			if resp.StatusCode != tc.status {
				t.Errorf("StatusCode = %d, wants %d", resp.StatusCode, tc.status)
			}
		})
	}
}

func setup(providers []TokenProvider) http.Handler {
	r := mux.NewRouter()
	store := storage.NewMemoryStorage("dam-min", "testdata/config")
	r.HandleFunc(tokensPath, handlerfactory.MakeHandler(store, ListTokensFactory(tokensPath, providers))).Methods(http.MethodGet)
	r.HandleFunc(tokenPath, handlerfactory.MakeHandler(store, DeleteTokenFactory(tokenPath, providers))).Methods(http.MethodDelete)
	return r
}

type stubTokenProvider struct {
	listResp         []*Token
	listErr          error
	deleteReqUser    string
	deleteReqTokenID string
	deleteErr        error
}

func (s *stubTokenProvider) ListTokens(ctx context.Context, user string) ([]*Token, error) {
	return s.listResp, s.listErr
}

func (s *stubTokenProvider) DeleteToken(ctx context.Context, user, tokenID string) error {
	s.deleteReqUser = user
	s.deleteReqTokenID = tokenID
	return s.deleteErr
}

func (s *stubTokenProvider) TokenPrefix() string {
	return "gcp"
}
