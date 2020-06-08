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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"github.com/gorilla/mux" /* copybara-comment */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/go-openapi/strfmt" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/apis/hydraapi" /* copybara-comment: hydraapi */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/handlerfactory" /* copybara-comment: handlerfactory */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakehydra" /* copybara-comment: fakehydra */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/httptestclient" /* copybara-comment: httptestclient */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	topb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/store/tokens" /* copybara-comment: go_proto */
	tpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/tokens/v1" /* copybara-comment: go_proto */
)

const (
	hydraAdminURL = "http://admin.example.com"
	issuer        = "http://example.com/"
)

var (
	clients = map[string]*cpb.Client{
		"test": &cpb.Client{
			ClientId: "t1",
			Ui: map[string]string{
				"descriptions": "abcdefg",
			},
		},
	}
)

func TestListTokens_Hydra(t *testing.T) {
	handler, stub, h, _ := setupHydraTest()
	stub.respClients = clients

	sub := "u-0001"
	h.ListConsentsResp = []*hydraapi.PreviousConsentSession{
		{
			GrantedAudience: []string{"a1", "a2"},
			GrantedScope:    []string{"s1", "s2"},
			HandledAt:       strfmt.NewDateTime(),
			ConsentRequest: &hydraapi.ConsentRequest{
				Subject: sub,
				Client:  &hydraapi.Client{Name: "test"},
			},
			Session: &hydraapi.ConsentRequestSessionData{
				AccessToken: map[string]interface{}{"tid": "t-0001"},
			},
		},
		{
			GrantedAudience: []string{"a1", "a2"},
			GrantedScope:    []string{"s1", "s2"},
			HandledAt:       strfmt.NewDateTime(),
			ConsentRequest: &hydraapi.ConsentRequest{
				Subject: sub,
				Client:  &hydraapi.Client{Name: "deleted-client"},
			},
			Session: &hydraapi.ConsentRequestSessionData{
				AccessToken: map[string]interface{}{"tid": "t-0002"},
			},
		},
		{
			GrantedAudience: []string{"a1", "a2"},
			GrantedScope:    []string{"s1", "s2"},
			HandledAt:       strfmt.NewDateTime(),
			ConsentRequest: &hydraapi.ConsentRequest{
				Subject: sub,
				Client:  &hydraapi.Client{Name: "test"},
			},
			Session: &hydraapi.ConsentRequestSessionData{
			},
		},
	}

	u := "http://example.com/dam/v1alpha/users/u-0001/tokens"
	r := httptest.NewRequest(http.MethodGet, u, nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, wants %d", resp.StatusCode, http.StatusOK)
	}

	got := &tpb.ListTokensResponse{}
	httputils.MustDecodeJSONPBResp(t, resp, got)
	want := &tpb.ListTokensResponse{
		Tokens: []*tpb.Token{
			{
				Name:     encodeTokenName(sub, "hydra", "t-0001"),
				Issuer:   issuer,
				IssuedAt: 0,
				Subject:  sub,
				Type:     "hydra",
				Audience: "a1,a2",
				Scope:    "s1 s2",
				Client: &tpb.Client{
					Id:   "t1",
					Name: "test",
					Ui:   map[string]string{"descriptions": "abcdefg"},
				},
			},
			{
				Name:     encodeTokenName(sub, "hydra", "t-0002"),
				Issuer:   issuer,
				IssuedAt: 0,
				Subject:  sub,
				Type:     "hydra",
				Audience: "a1,a2",
				Scope:    "s1 s2",
				Client:   &tpb.Client{},
			},
		},
	}

	if d := cmp.Diff(want, got, protocmp.Transform()); len(d) > 0 {
		t.Errorf("listToken (-want, +got): %s", d)
	}
}

func TestListTokens_Hydra_HydraAPIError(t *testing.T) {
	handler, stub, h, _ := setupHydraTest()
	stub.respClients = clients
	h.ListConsentsErr = &hydraapi.GenericError{Code: http.StatusNotFound}
	u := "http://example.com/dam/v1alpha/users/u-0001/tokens"
	r := httptest.NewRequest(http.MethodGet, u, nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	resp := w.Result()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("StatusCode = %d, wants %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestListTokens_Hydra_GetClientsError(t *testing.T) {
	handler, stub, h, _ := setupHydraTest()
	stub.respErr = status.Errorf(codes.Unavailable, "Unavailable")
	h.ListConsentsResp = []*hydraapi.PreviousConsentSession{}
	u := "http://example.com/dam/v1alpha/users/u-0001/tokens"
	r := httptest.NewRequest(http.MethodGet, u, nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	resp := w.Result()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("StatusCode = %d, wants %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
}

func TestDeleteToken_Hydra(t *testing.T) {
	handler, _, _, store := setupHydraTest()
	u := "http://example.com/dam/v1alpha/" + encodeTokenName("u-0001", "hydra", "t-0001")
	r := httptest.NewRequest(http.MethodDelete, u, nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, wants %d", resp.StatusCode, http.StatusOK)
	}

	pending := &topb.PendingDeleteToken{}
	if err := store.Read(storage.PendingDeleteTokenDatatype, storage.DefaultRealm, "u-0001", "t-0001", storage.LatestRev, pending); err != nil {
		t.Fatalf("Read PendingDeleteToken failed: %v", err)
	}
}

func setupHydraTest() (http.Handler, *clientStub, *fakehydra.Server, storage.Store) {
	hydraRouter := mux.NewRouter()
	h := fakehydra.New(hydraRouter)
	httpClient = httptestclient.New(hydraRouter)

	stub := &clientStub{}

	providers := []TokenProvider{
		&Hydra{
			hydraAdminURL: hydraAdminURL,
			issuer:        issuer,
			clients:       stub.clients,
		},
	}

	store := storage.NewMemoryStorage("dam-min", "testdata/config")
	r := mux.NewRouter()
	r.HandleFunc(tokensPath, handlerfactory.MakeHandler(store, ListTokensFactory(tokensPath, providers, store))).Methods(http.MethodGet)
	r.HandleFunc(tokenPath, handlerfactory.MakeHandler(store, DeleteTokenFactory(tokenPath, providers, store))).Methods(http.MethodDelete)

	return r, stub, h, store
}

type clientStub struct {
	respClients map[string]*cpb.Client
	respErr     error
}

func (s *clientStub) clients(tx storage.Tx) (map[string]*cpb.Client, error) {
	return s.respClients, s.respErr
}
