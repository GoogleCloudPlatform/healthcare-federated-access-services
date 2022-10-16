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
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"google.golang.org/api/option" /* copybara-comment: option */
	"github.com/gorilla/mux" /* copybara-comment */
	"google.golang.org/grpc" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/adapter" /* copybara-comment: adapter */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds" /* copybara-comment: clouds */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/handlerfactory" /* copybara-comment: handlerfactory */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/saw" /* copybara-comment: saw */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakegrpc" /* copybara-comment: fakegrpc */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakeiam" /* copybara-comment: fakeiam */
	tpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/tokens/v1" /* copybara-comment: go_proto */

	iamgrpcpb "google.golang.org/genproto/googleapis/iam/admin/v1" /* copybara-comment: iam_go_grpc */
	iamadmin "cloud.google.com/go/iam/admin/apiv1" /* copybara-comment */
)

func TestGCP_ListTokens(t *testing.T) {
	h, wh, iamSrv, cleanup := setupGCPTest(t)
	defer cleanup()

	params := &clouds.ResourceTokenCreationParams{
		AccountProject: saProject,
		Items:          []map[string]string{},
		Roles:          []string{},
		Scopes:         []string{"fake-scope"},
		BillingProject: "fake-billing-project",
	}

	ctx := context.Background()

	user := "u-0001"
	userID := ga4gh.TokenUserID(&ga4gh.Identity{Subject: user, Issuer: broker}, adapter.SawMaxUserIDLength)
	if _, err := wh.MintTokenWithTTL(ctx, userID, 10*time.Hour, 10*time.Hour, 100, params); err != nil {
		t.Errorf("MintTokenWithTTL() failed: %v", err)
	}

	u := "http://example.com/dam/v1alpha/users/u-0001/tokens"
	r := httptest.NewRequest(http.MethodGet, u, nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	resp := w.Result()
	got := &tpb.ListTokensResponse{}
	httputils.MustDecodeJSONPBResp(t, resp, got)

	state := <-iamSrv.State

	ss := strings.Split(state.Keys[0].Name, "/")
	tokenName := ss[len(ss)-1]
	want := &tpb.ListTokensResponse{
		Tokens: []*tpb.Token{
			{
				Name:      encodeTokenName("u-0001", "gcp", tokenName),
				IssuedAt:  state.Keys[0].ValidAfterTime.Seconds,
				ExpiresAt: state.Keys[0].ValidBeforeTime.Seconds,
				Type:      "gcp",
				Client:    &tpb.Client{},
			},
		},
	}

	if d := cmp.Diff(want, got, protocmp.Transform()); len(d) > 0 {
		t.Errorf("listToken (-want, +got): %s", d)
	}
}

func TestGCP_DeleteTokenTokens(t *testing.T) {
	h, wh, iamSrv, cleanup := setupGCPTest(t)
	defer cleanup()

	params := &clouds.ResourceTokenCreationParams{
		AccountProject: saProject,
		Items:          []map[string]string{},
		Roles:          []string{},
		Scopes:         []string{"fake-scope"},
		BillingProject: "fake-billing-project",
	}

	ctx := context.Background()

	user := "u-0001"
	userID := ga4gh.TokenUserID(&ga4gh.Identity{Subject: user, Issuer: broker}, adapter.SawMaxUserIDLength)
	if _, err := wh.MintTokenWithTTL(ctx, userID, 10*time.Hour, 10*time.Hour, 100, params); err != nil {
		t.Errorf("MintTokenWithTTL() failed: %v", err)
	}

	state := <-iamSrv.State
	iamSrv.State <- state

	ss := strings.Split(state.Keys[0].Name, "/")
	tokenName := encodeTokenName(user, "gcp", ss[len(ss)-1])

	u := "http://example.com/dam/v1alpha/" + tokenName
	r := httptest.NewRequest(http.MethodDelete, u, nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, wants %d", resp.StatusCode, http.StatusOK)
	}

	state = <-iamSrv.State
	if len(state.Keys) > 0 {
		t.Errorf("state.Keys should be empty: %v", state.Keys)
	}
}

const (
	saProject = "fake-account-project"
	broker    = "https://example.com"
)

func setupGCPTest(t *testing.T) (http.Handler, *saw.AccountWarehouse, *fakeiam.Admin, func() error) {
	t.Helper()
	ctx := context.Background()
	var (
		err     error
		cleanup func() error
	)

	rpc, cleanup := fakegrpc.New()

	iamSrv := fakeiam.NewAdmin()
	iamgrpcpb.RegisterIAMServer(rpc.Server, iamSrv)

	rpc.Start()

	opts := []option.ClientOption{
		option.WithGRPCConn(rpc.Client),
		option.WithoutAuthentication(),
		option.WithGRPCDialOption(grpc.WithInsecure()),
	}

	iam, err := iamadmin.NewIamClient(ctx, opts...)
	if err != nil {
		t.Fatalf("iamadmin.NewService() failed: %v", err)
	}

	store := storage.NewMemoryStorage("dam-min", "testdata/config")
	warehouse := saw.New(store, iam, nil, nil, nil, nil, nil)

	gcp := NewGCPTokenManager(saProject, broker, warehouse)

	r := mux.NewRouter()
	r.HandleFunc(tokensPath, handlerfactory.MakeHandler(store, ListTokensFactory(tokensPath, []TokenProvider{gcp}, store))).Methods(http.MethodGet)
	r.HandleFunc(tokenPath, handlerfactory.MakeHandler(store, DeleteTokenFactory(tokenPath, []TokenProvider{gcp}, store))).Methods(http.MethodDelete)

	return r, warehouse, iamSrv, cleanup
}
