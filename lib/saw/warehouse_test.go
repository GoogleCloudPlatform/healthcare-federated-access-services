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

package saw

import (
	"context"
	"testing"
	"time"

	iamadmin "cloud.google.com/go/iam/admin/apiv1" /* copybara-comment: admin */
	iamcreds "cloud.google.com/go/iam/credentials/apiv1" /* copybara-comment: credentials */
	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"google.golang.org/api/bigquery/v2" /* copybara-comment: bigquery */
	"google.golang.org/api/cloudresourcemanager/v1" /* copybara-comment: cloudresourcemanager */
	"google.golang.org/api/option" /* copybara-comment: option */
	gcs "google.golang.org/api/storage/v1" /* copybara-comment: storage */
	"google.golang.org/grpc" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds" /* copybara-comment: clouds */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakegrpc" /* copybara-comment: fakegrpc */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakeiam" /* copybara-comment: fakeiam */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakestore" /* copybara-comment: fakestore */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/timeutil" /* copybara-comment: timeutil */

	iamgrpcpb "google.golang.org/genproto/googleapis/iam/admin/v1" /* copybara-comment: iam_go_grpc */
	iamcredsgrpcpb "google.golang.org/genproto/googleapis/iam/credentials/v1" /* copybara-comment: iamcredentials_go_grpc */
	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
)

func TestNew(t *testing.T) {
	store := fakestore.New()
	_ = MustNew(context.Background(), store, option.WithoutAuthentication(), option.WithGRPCDialOption(grpc.WithInsecure()))
}

func TestSAW_GetAccountKey(t *testing.T) {
	ctx := context.Background()

	fix, cleanup := newFix(t)
	defer cleanup()

	store := fakestore.New()
	saw := New(store, fix.iam, fix.creds, fix.crm, fix.gcs, fix.bqds, nil)

	params := &clouds.ResourceTokenCreationParams{
		AccountProject: "fake-account-project",
		Items:          []map[string]string{},
		Roles:          []string{},
		Scopes:         []string{"fake-scope"},
		BillingProject: "fake-billing-project",
	}

	got, err := saw.GetAccountKey(ctx, "fake-id", time.Minute, time.Hour, 100, params)
	if err != nil {
		t.Errorf("GetAccountKey() failed: %v", err)
	}

	want := &clouds.ResourceTokenResult{
		Format:  "base64",
		Account: "ie652a310ecf7b4ec1771e62d53609@fake-account-project.iam.gserviceaccount.com",
		Token:   "projects/fake-account-project/serviceAccounts/ie652a310ecf7b4ec1771e62d53609@fake-account-project.iam.gserviceaccount.com/keys/fake-key-id-0/fake-private-key",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("saw.GetAccountKey() returned diff (-want +got):\n%s", diff)
	}
}

func TestSAW_MintTokenWithTTL(t *testing.T) {
	ctx := context.Background()

	fix, cleanup := newFix(t)
	defer cleanup()

	store := fakestore.New()
	saw := New(store, fix.iam, fix.creds, fix.crm, fix.gcs, fix.bqds, nil)

	params := &clouds.ResourceTokenCreationParams{
		AccountProject: "fake-account-project",
		Items:          []map[string]string{},
		Roles:          []string{},
		Scopes:         []string{"fake-scope"},
		BillingProject: "fake-billing-project",
	}

	if _, err := saw.GetAccountKey(ctx, "fake-id", time.Minute, time.Hour, 100, params); err != nil {
		t.Errorf("GetAccountKey() failed: %v", err)
	}

	got, err := saw.MintTokenWithTTL(ctx, "fake-id", time.Minute, time.Hour, 100, params)
	if err != nil {
		t.Errorf("MintTokenWithTTL() failed: %v", err)
	}

	want := &clouds.ResourceTokenResult{
		Format:  "base64",
		Account: "ie652a310ecf7b4ec1771e62d53609@fake-account-project.iam.gserviceaccount.com",
		Token:   "projects/-/serviceAccounts/ie652a310ecf7b4ec1771e62d53609@fake-account-project.iam.gserviceaccount.com/token-0",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("saw.MintTokenWithTTL() returned diff (-want +got):\n%s", diff)
	}
}

func TestSAW_GetTokenMetadata(t *testing.T) {
	ctx := context.Background()

	fix, cleanup := newFix(t)
	defer cleanup()

	store := fakestore.New()
	saw := New(store, fix.iam, fix.creds, fix.crm, fix.gcs, fix.bqds, nil)

	params := &clouds.ResourceTokenCreationParams{
		AccountProject: "fake-account-project",
		Items:          []map[string]string{},
		Roles:          []string{},
		Scopes:         []string{"fake-scope"},
		BillingProject: "fake-billing-project",
	}

	if _, err := saw.GetAccountKey(ctx, "fake-id", time.Minute, time.Hour, 100, params); err != nil {
		t.Errorf("GetAccountKey() failed: %v", err)
	}

	if _, err := saw.MintTokenWithTTL(ctx, "fake-id", time.Minute, time.Hour, 100, params); err != nil {
		t.Errorf("MintTokenWithTTL() failed: %v", err)
	}

	got, err := saw.GetTokenMetadata(ctx, "fake-account-project", "fake-id", "fake-key-id-0")
	if err != nil {
		t.Errorf("GetTokenMetadata() failed: %v", err)
	}

	state := <-fix.credsSrv.State
	exp := timeutil.Time(state.Tokens[0].ExpireTime)
	want := &cpb.TokenMetadata{
		Name:     "fake-key-id-0",
		IssuedAt: timeutil.RFC3339(timeutil.TimestampProto(exp.Add(-1 * time.Hour))),
		Expires:  timeutil.RFC3339(timeutil.TimestampProto(exp.Add(23 * time.Hour))),
	}
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("saw.GetTokenMetadata() returned diff (-want +got):\n%s", diff)
	}
}

func TestSAW_ListTokenMetadata(t *testing.T) {
	ctx := context.Background()

	fix, cleanup := newFix(t)
	defer cleanup()

	store := fakestore.New()
	saw := New(store, fix.iam, fix.creds, fix.crm, fix.gcs, fix.bqds, nil)

	params := &clouds.ResourceTokenCreationParams{
		AccountProject: "fake-account-project",
		Items:          []map[string]string{},
		Roles:          []string{},
		Scopes:         []string{"fake-scope"},
		BillingProject: "fake-billing-project",
	}

	if _, err := saw.GetAccountKey(ctx, "fake-id", time.Minute, time.Hour, 100, params); err != nil {
		t.Errorf("GetAccountKey() failed: %v", err)
	}

	if _, err := saw.MintTokenWithTTL(ctx, "fake-id", time.Minute, time.Hour, 100, params); err != nil {
		t.Errorf("MintTokenWithTTL() failed: %v", err)
	}

	got, err := saw.ListTokenMetadata(ctx, "fake-account-project", "fake-id")
	if err != nil {
		t.Errorf("GetTokenMetadata() failed: %v", err)
	}

	state := <-fix.credsSrv.State
	exp := timeutil.Time(state.Tokens[0].ExpireTime)
	want := []*cpb.TokenMetadata{{
		Name:     "fake-key-id-0",
		IssuedAt: timeutil.RFC3339(timeutil.TimestampProto(exp.Add(-1 * time.Hour))),
		Expires:  timeutil.RFC3339(timeutil.TimestampProto(exp.Add(23 * time.Hour))),
	}}
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("saw.GetTokenMetadata() returned diff (-want +got):\n%s", diff)
	}
}

func TestSAW_DeleteTokens(t *testing.T) {
	ctx := context.Background()

	fix, cleanup := newFix(t)
	defer cleanup()

	store := fakestore.New()
	saw := New(store, fix.iam, fix.creds, fix.crm, fix.gcs, fix.bqds, nil)

	params := &clouds.ResourceTokenCreationParams{
		AccountProject: "fake-account-project",
		Items:          []map[string]string{},
		Roles:          []string{},
		Scopes:         []string{"fake-scope"},
		BillingProject: "fake-billing-project",
	}

	if _, err := saw.GetAccountKey(ctx, "fake-id", time.Minute, time.Hour, 100, params); err != nil {
		t.Errorf("GetAccountKey() failed: %v", err)
	}

	if _, err := saw.MintTokenWithTTL(ctx, "fake-id", time.Minute, time.Hour, 100, params); err != nil {
		t.Errorf("MintTokenWithTTL() failed: %v", err)
	}

	if err := saw.DeleteTokens(ctx, "fake-account-project", "fake-id", nil); err != nil {
		t.Errorf("DeleteTokens() failed: %v", err)
	}

	state := <-fix.iamSrv.State
	if len(state.Keys) != 0 {
		t.Errorf("saw.DeleteTokens() didn't delete the keys.")
	}
}

func TestSAW_GetServiceAccounts(t *testing.T) {
	ctx := context.Background()

	fix, cleanup := newFix(t)
	defer cleanup()

	store := fakestore.New()
	saw := New(store, fix.iam, fix.creds, fix.crm, fix.gcs, fix.bqds, nil)

	params := &clouds.ResourceTokenCreationParams{
		AccountProject: "fake-account-project",
		Items:          []map[string]string{},
		Roles:          []string{},
		Scopes:         []string{"fake-scope"},
		BillingProject: "fake-billing-project",
	}

	if _, err := saw.GetAccountKey(ctx, "fake-id", time.Minute, time.Hour, 100, params); err != nil {
		t.Errorf("GetAccountKey() failed: %v", err)
	}

	nctx, cancel := context.WithCancel(ctx)
	defer cancel()
	c, err := saw.GetServiceAccounts(nctx, "fake-account-project")
	if err != nil {
		t.Errorf("GetServiceAccounts() failed: %v", err)
	}

	var got []*clouds.Account
	for a := range c {
		got = append(got, a)
	}

	want := []*clouds.Account{{
		ID:          "ie652a310ecf7b4ec1771e62d53609@fake-account-project.iam.gserviceaccount.com",
		DisplayName: "fake-id",
	}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("saw.GetServiceAccounts() returned diff (-want +got):\n%s", diff)
	}
}

func TestSAW_RemoveServiceAccount(t *testing.T) {
	ctx := context.Background()

	fix, cleanup := newFix(t)
	defer cleanup()

	store := fakestore.New()
	saw := New(store, fix.iam, fix.creds, fix.crm, fix.gcs, fix.bqds, nil)

	params := &clouds.ResourceTokenCreationParams{
		AccountProject: "fake-account-project",
		Items:          []map[string]string{},
		Roles:          []string{},
		Scopes:         []string{"fake-scope"},
		BillingProject: "fake-billing-project",
	}

	if _, err := saw.GetAccountKey(ctx, "fake-id", time.Minute, time.Hour, 100, params); err != nil {
		t.Errorf("GetAccountKey() failed: %v", err)
	}

	if err := saw.RemoveServiceAccount(ctx, "fake-account-project", "fake-id"); err != nil {
		t.Errorf("RemoveServiceAccount() failed: %v", err)
	}
}

func TestSAW_ManageAccountKeys_RemovesExpiredKeys(t *testing.T) {
	ctx := context.Background()

	fix, cleanup := newFix(t)
	defer cleanup()

	store := fakestore.New()
	saw := New(store, fix.iam, fix.creds, fix.crm, fix.gcs, fix.bqds, nil)

	params := &clouds.ResourceTokenCreationParams{
		AccountProject: "fake-account-project",
		Items:          []map[string]string{},
		Roles:          []string{},
		Scopes:         []string{"fake-scope"},
		BillingProject: "fake-billing-project",
	}

	if _, err := saw.GetAccountKey(ctx, "fake-id", time.Minute, time.Hour, 100, params); err != nil {
		t.Errorf("GetAccountKey() failed: %v", err)
	}
	if _, err := saw.GetAccountKey(ctx, "fake-id", time.Minute, time.Hour, 100, params); err != nil {
		t.Errorf("GetAccountKey() failed: %v", err)
	}
	if _, err := saw.GetAccountKey(ctx, "fake-id", time.Minute, time.Hour, 100, params); err != nil {
		t.Errorf("GetAccountKey() failed: %v", err)
	}

	active, removed, err := saw.ManageAccountKeys(ctx, "fake-project-id", EmailID("fake-project-id", "fake-id"), time.Minute, time.Hour, time.Now(), 2)
	if err != nil {
		t.Errorf("ManageAccountKeys() failed: %v", err)
	}
	if active != 2 || removed != 1 {
		t.Errorf("ManageAccountKeys() = active:%v, removed:%v, want active:%v, removed:%v", active, removed, 2, 1)
	}

	active, removed, err = saw.ManageAccountKeys(ctx, "fake-project-id", EmailID("fake-project-id", "fake-id"), time.Minute, time.Hour, time.Now().Add(48*time.Hour), 2)
	if err != nil {
		t.Errorf("ManageAccountKeys() failed: %v", err)
	}
	if active != 0 || removed != 2 {
		t.Errorf("ManageAccountKeys() = active:%v, removed:%v, want active:%v, removed:%v", active, removed, 0, 2)
	}
}

// Fix is a test fixture.
type Fix struct {
	rpc      *fakegrpc.Fake
	iam      *iamadmin.IamClient
	iamSrv   *fakeiam.Admin
	creds    *iamcreds.IamCredentialsClient
	credsSrv *fakeiam.Creds
	bqds     BQPolicy
	crm      CRMPolicy
	gcs      GCSPolicy
}

func newFix(t *testing.T) (*Fix, func() error) {
	t.Helper()
	ctx := context.Background()
	var (
		err     error
		cleanup func() error
	)

	f := &Fix{
		bqds: &fakeBQ{},
		crm:  &fakeCRM{},
		gcs:  &fakeGCS{},
	}
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

	return f, cleanup
}

type fakeGCS struct {
}

func (f *fakeGCS) Get(ctx context.Context, bkt string, billingProject string) (*gcs.Policy, error) {
	return nil, nil
}

func (f *fakeGCS) Set(ctx context.Context, bkt string, billingProject string, policy *gcs.Policy) error {
	return nil
}

type fakeBQ struct {
}

func (f *fakeBQ) Get(ctx context.Context, project string, dataset string) (*bigquery.Dataset, error) {
	return nil, nil
}

func (f *fakeBQ) Set(ctx context.Context, project string, dataset string, ds *bigquery.Dataset) error {
	return nil
}

type fakeCRM struct {
}

func (f *fakeCRM) Get(ctx context.Context, project string) (*cloudresourcemanager.Policy, error) {
	return nil, nil
}

func (f *fakeCRM) Set(ctx context.Context, project string, policy *cloudresourcemanager.Policy) error {
	return nil
}
