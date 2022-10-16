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

package faketokensapi

import (
	"context"
	"testing"
	"time"

	iamadmin "cloud.google.com/go/iam/admin/apiv1" /* copybara-comment */
	iamcreds "cloud.google.com/go/iam/credentials/apiv1" /* copybara-comment */
	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"google.golang.org/api/option" /* copybara-comment: option */
	"google.golang.org/grpc" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/saw" /* copybara-comment: saw */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakegrpc" /* copybara-comment: fakegrpc */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakeiam" /* copybara-comment: fakeiam */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakestore" /* copybara-comment: fakestore */

	iamgrpcpb "google.golang.org/genproto/googleapis/iam/admin/v1" /* copybara-comment: iam_go_grpc */
	iampb "google.golang.org/genproto/googleapis/iam/admin/v1" /* copybara-comment: iam_go_proto */
	iamcredsgrpcpb "google.golang.org/genproto/googleapis/iam/credentials/v1" /* copybara-comment: iamcredentials_go_grpc */
	dampb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
	tpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/tokens/v1" /* copybara-comment: go_proto */
)

func TestDAMTokens_List(t *testing.T) {
	ctx := context.Background()
	f, cleanup := newFix(t)
	defer cleanup()
	MustWriteRealmConfig(t, f.store, storage.DefaultRealm, &dampb.DamConfig{Options: &dampb.ConfigOptions{GcpServiceAccountProject: "fake-project"}})

	s := NewDAMTokens(f.store, f.saw)

	// Create a token on GCP.
	user := "fake-user"
	accountID := saw.HashExternalID(user) // "i927b605a236d4034b8a202abef46e"
	before := time.Now()
	f.iamSrv.CreateServiceAccount(ctx, &iampb.CreateServiceAccountRequest{Name: "projects/fake-project", AccountId: accountID})
	f.iamSrv.CreateServiceAccountKey(ctx, &iampb.CreateServiceAccountKeyRequest{Name: fakeiam.SAName("fake-project", accountID)})
	after := time.Now()

	got, err := s.ListTokens(ctx, &tpb.ListTokensRequest{Parent: "users/" + user})
	if err != nil {
		t.Fatalf("ListTokens() failed: %v", err)
	}

	iat := time.Unix(got.Tokens[0].GetIssuedAt(), 0)
	if iat.Before(before.Add(-time.Second)) || iat.After(after.Add(time.Second)) {
		t.Errorf("ListTokens(): token is issued at %v, want in [%v,%v]", iat, before, after)
	}
	exp := time.Unix(got.Tokens[0].GetExpiresAt(), 0)
	if exp.Before(before.Add(-time.Second).Add(24*time.Hour)) || exp.After(after.Add(time.Second).Add(24*time.Hour)) {
		t.Errorf("ListTokens(): token expires at %v, want in [%v,%v]", exp, before, after)
	}
	// TODO: use protocmp.IgnoreFields(&tpb.Token{}, "expires_at", "issued_at") instead when it works.
	got.Tokens[0].IssuedAt = 0
	got.Tokens[0].ExpiresAt = 0
	want := &tpb.ListTokensResponse{Tokens: []*tpb.Token{{Name: "users/fake-user/tokens/fake-key-id-0"}}}
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("ListTokens() returned diff (-want +got):\n%s", diff)
	}
}

func TestDAMTokens_Delete(t *testing.T) {
	ctx := context.Background()
	f, cleanup := newFix(t)
	defer cleanup()
	MustWriteRealmConfig(t, f.store, storage.DefaultRealm, &dampb.DamConfig{Options: &dampb.ConfigOptions{GcpServiceAccountProject: "fake-project"}})

	s := NewDAMTokens(f.store, f.saw)

	// Create a token on GCP.
	user := "fake-user"
	accountID := saw.HashExternalID(user) // "i927b605a236d4034b8a202abef46e"
	f.iamSrv.CreateServiceAccount(ctx, &iampb.CreateServiceAccountRequest{Name: "projects/fake-project", AccountId: accountID})
	f.iamSrv.CreateServiceAccountKey(ctx, &iampb.CreateServiceAccountKeyRequest{Name: fakeiam.SAName("fake-project", accountID)})

	if _, err := s.DeleteToken(ctx, &tpb.DeleteTokenRequest{Name: "users/" + user + "/tokens/" + "fake-key-id-0"}); err != nil {
		t.Fatalf("DeleteToken() failed: %v", err)
	}

	got, err := s.ListTokens(ctx, &tpb.ListTokensRequest{Parent: "users/" + user})
	if err != nil {
		t.Fatalf("ListTokens() failed: %v", err)
	}
	if len(got.GetTokens()) != 0 {
		t.Fatal("DeleteToken(): didn't delete the token")
	}
}

// Fix is a test fixture.
type Fix struct {
	rpc      *fakegrpc.Fake
	iam      *iamadmin.IamClient
	iamSrv   *fakeiam.Admin
	creds    *iamcreds.IamCredentialsClient
	credsSrv *fakeiam.Creds
	saw      *saw.AccountWarehouse
	store    *fakestore.Store
}

func newFix(t *testing.T) (*Fix, func() error) {
	t.Helper()
	ctx := context.Background()
	var (
		err     error
		cleanup func() error
	)

	f := &Fix{}
	f.store = fakestore.New()
	f.rpc, cleanup = fakegrpc.New()

	f.iamSrv = fakeiam.NewAdmin()
	iamgrpcpb.RegisterIAMServer(f.rpc.Server, f.iamSrv)

	f.credsSrv = fakeiam.NewCreds()
	iamcredsgrpcpb.RegisterIAMCredentialsServer(f.rpc.Server, f.credsSrv)

	f.rpc.Start()

	opts := []option.ClientOption{
		option.WithGRPCConn(f.rpc.Client),
		option.WithoutAuthentication(),
		option.WithGRPCDialOption(grpc.WithInsecure()),
	}

	f.iam, err = iamadmin.NewIamClient(ctx, opts...)
	if err != nil {
		t.Fatalf("iamadmin.NewService() failed: %v", err)
	}

	f.creds, err = iamcreds.NewIamCredentialsClient(ctx, opts...)
	if err != nil {
		t.Fatalf("iamcreds.NewIamCredentialsClient() failed: %v", err)
	}

	f.saw = saw.New(nil, f.iam, f.creds, nil, nil, nil, nil)

	return f, cleanup
}

func TestParentRE(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{
			in:   "users/fake-user",
			want: []string{"users/fake-user", "fake-user"},
		},
		{
			in:   "",
			want: nil,
		},
		{
			in:   "users",
			want: nil,
		},
		{
			in:   "EXTRAusers/fake-user",
			want: nil,
		},
		{
			in:   "EXTRA/users/fake-user",
			want: nil,
		},
		{
			in:   "users/fake-user/EXTRA",
			want: nil,
		},
	}

	for _, tc := range tests {
		got := parentRE.FindStringSubmatch(tc.in)
		if diff := cmp.Diff(tc.want, got); diff != "" {
			t.Errorf("parentRE.FindStringSubmatch(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestResourceRE(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{
			in:   "users/fake-user/tokens/fake-token",
			want: []string{"users/fake-user/tokens/fake-token", "fake-user", "fake-token"},
		},
		{
			in:   "",
			want: nil,
		},
		{
			in:   "users",
			want: nil,
		},
		{
			in:   "users/fake-user",
			want: nil,
		},
		{
			in:   "users/fake-user/tokens",
			want: nil,
		},
		{
			in:   "EXTRAusers/fake-user/tokens/fake-token",
			want: nil,
		},
		{
			in:   "EXTRA/users/fake-user/tokens/fake-token",
			want: nil,
		},
		{
			in:   "users/fake-user//tokens/fake-token/EXTRA",
			want: nil,
		},
	}

	for _, tc := range tests {
		got := resourceRE.FindStringSubmatch(tc.in)
		if diff := cmp.Diff(tc.want, got); diff != "" {
			t.Errorf("resourceRE.FindStringSubmatch(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func MustWriteRealmConfig(t *testing.T, store *fakestore.Store, realm string, cfg *dampb.DamConfig) {
	if err := store.Write(storage.ConfigDatatype, realm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, cfg, nil); err != nil {
		t.Fatalf("failed to setup the store")
	}
}
