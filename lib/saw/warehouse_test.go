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
	"crypto/sha256"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	glog "github.com/golang/glog" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
	"github.com/golang/protobuf/ptypes" /* copybara-comment */
	iamadmin "cloud.google.com/go/iam/admin/apiv1" /* copybara-comment: admin */
	iamcreds "cloud.google.com/go/iam/credentials/apiv1" /* copybara-comment: credentials */
	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"google.golang.org/api/bigquery/v2" /* copybara-comment: bigquery */
	"google.golang.org/api/cloudresourcemanager/v1" /* copybara-comment: cloudresourcemanager */
	"google.golang.org/api/option" /* copybara-comment: option */
	gcs "google.golang.org/api/storage/v1" /* copybara-comment: storage */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */
	"github.com/pborman/uuid" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds" /* copybara-comment: clouds */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakegrpc" /* copybara-comment: fakegrpc */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakestore" /* copybara-comment: fakestore */

	iamgrpcpb "google.golang.org/genproto/googleapis/iam/admin/v1" /* copybara-comment: iam_go_grpc */
	iampb "google.golang.org/genproto/googleapis/iam/admin/v1" /* copybara-comment: iam_go_proto */
	iamcredscpb "google.golang.org/genproto/googleapis/iam/credentials/v1" /* copybara-comment: common_go_proto */
	iamcredsgrpcpb "google.golang.org/genproto/googleapis/iam/credentials/v1" /* copybara-comment: iamcredentials_go_grpc */
	epb "github.com/golang/protobuf/ptypes/empty" /* copybara-comment */
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
	saw, err := New(store, fix.iam, fix.creds, fix.crm, fix.gcs, fix.bqds, nil)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

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
	saw, err := New(store, fix.iam, fix.creds, fix.crm, fix.gcs, fix.bqds, nil)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

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
		Token:   "token-1",
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
	saw, err := New(store, fix.iam, fix.creds, fix.crm, fix.gcs, fix.bqds, nil)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

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

	exp := Time(fix.credsSrv.tokens[0].ExpireTime)
	want := &cpb.TokenMetadata{
		Name:     "fake-key-id-0",
		IssuedAt: RFC3339(Timestamp(exp.Add(-1 * time.Hour))),
		Expires:  RFC3339(Timestamp(exp.Add(23 * time.Hour))),
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
	saw, err := New(store, fix.iam, fix.creds, fix.crm, fix.gcs, fix.bqds, nil)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

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

	exp := Time(fix.credsSrv.tokens[0].ExpireTime)
	want := []*cpb.TokenMetadata{{
		Name:     "fake-key-id-0",
		IssuedAt: RFC3339(Timestamp(exp.Add(-1 * time.Hour))),
		Expires:  RFC3339(Timestamp(exp.Add(23 * time.Hour))),
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
	saw, err := New(store, fix.iam, fix.creds, fix.crm, fix.gcs, fix.bqds, nil)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

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

	if len(fix.iamSrv.keys) != 0 {
		t.Errorf("saw.DeleteTokens() didn't delete the keys.")
	}
}

func TestSAW_GetServiceAccounts(t *testing.T) {
	ctx := context.Background()

	fix, cleanup := newFix(t)
	defer cleanup()

	store := fakestore.New()
	saw, err := New(store, fix.iam, fix.creds, fix.crm, fix.gcs, fix.bqds, nil)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

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
	saw, err := New(store, fix.iam, fix.creds, fix.crm, fix.gcs, fix.bqds, nil)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

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
	saw, err := New(store, fix.iam, fix.creds, fix.crm, fix.gcs, fix.bqds, nil)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

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

	active, removed, err := saw.ManageAccountKeys(ctx, "fake-project-id", emailID("fake-project-id", "fake-id"), time.Minute, time.Hour, time.Now(), 2)
	if err != nil {
		t.Errorf("ManageAccountKeys() failed: %v", err)
	}
	if active != 2 || removed != 1 {
		t.Errorf("ManageAccountKeys() = active:%v, removed:%v, want active:%v, removed:%v", active, removed, 2, 1)
	}

	active, removed, err = saw.ManageAccountKeys(ctx, "fake-project-id", emailID("fake-project-id", "fake-id"), time.Minute, time.Hour, time.Now().Add(48*time.Hour), 2)
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
	iamSrv   *fakeIAM
	creds    *iamcreds.IamCredentialsClient
	credsSrv *fakeIAMCreds
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

	f.iamSrv = &fakeIAM{}
	iamgrpcpb.RegisterIAMServer(f.rpc.Server, f.iamSrv)

	f.credsSrv = &fakeIAMCreds{}
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

type fakeIAM struct {
	accounts []*iampb.ServiceAccount
	keys     []*iampb.ServiceAccountKey

	iamgrpcpb.IAMServer
}

func (f *fakeIAM) ListServiceAccounts(ctx context.Context, req *iampb.ListServiceAccountsRequest) (*iampb.ListServiceAccountsResponse, error) {
	glog.Infof("ListServiceAccountsReq: %v", req)
	resp := &iampb.ListServiceAccountsResponse{Accounts: f.accounts}
	glog.Infof("ListServiceAccountsResp: %v", resp)
	return proto.Clone(resp).(*iampb.ListServiceAccountsResponse), nil
}

func (f *fakeIAM) GetServiceAccount(ctx context.Context, req *iampb.GetServiceAccountRequest) (*iampb.ServiceAccount, error) {
	glog.Infof("GetServiceAccountReq: %v", req)
	name := req.Name
	for _, a := range f.accounts {
		if a.Name == name {
			glog.Infof("GetServiceAccountResp: %v", a)
			return a, nil
		}
	}
	return nil, status.Errorf(codes.NotFound, "service account with name %q not found", name)
}

func (f *fakeIAM) CreateServiceAccount(ctx context.Context, req *iampb.CreateServiceAccountRequest) (*iampb.ServiceAccount, error) {
	glog.Infof("CreateServiceAccountReq: %v", req)
	proj := strings.Split(req.Name, "/")[1]
	email := fmt.Sprintf("%v@%v.iam.gserviceaccount.com", req.AccountId, proj)
	name := fmt.Sprintf("projects/%v/serviceAccounts/%v", proj, email)
	guid := uuid.New()
	for _, a := range f.accounts {
		if a.Name == name {
			glog.Infof("CreateServiceAccountResp Already Exists: %v", a)
			return nil, status.Errorf(codes.AlreadyExists, "service account with name %q already exists", name)
		}
	}
	a := &iampb.ServiceAccount{
		Name:           name,
		UniqueId:       guid,
		Email:          email,
		ProjectId:      proj,
		Oauth2ClientId: guid,
		DisplayName:    req.GetServiceAccount().GetDisplayName(),
	}
	a.Etag = HashProto(a)

	proto.Merge(a, req.ServiceAccount)
	f.accounts = append(f.accounts, a)

	glog.Infof("CreateServiceAccountResp: %v", a)
	return a, nil
}

func (f *fakeIAM) DeleteServiceAccount(ctx context.Context, req *iampb.DeleteServiceAccountRequest) (*epb.Empty, error) {
	glog.Infof("DeleteServiceAccountReq: %v", req)
	name := req.Name
	var updated []*iampb.ServiceAccount
	for _, a := range f.accounts {
		if a.Name != name {
			updated = append(updated, a)
		}
	}
	f.accounts = updated
	return &epb.Empty{}, nil
}

func (f *fakeIAM) ListServiceAccountKeys(ctx context.Context, req *iampb.ListServiceAccountKeysRequest) (*iampb.ListServiceAccountKeysResponse, error) {
	glog.Infof("ListServiceAccountKeysReq: %v", req)
	resp := &iampb.ListServiceAccountKeysResponse{Keys: f.keys}
	glog.Infof("ListServiceAccountKeysResp: %v", resp)
	return proto.Clone(resp).(*iampb.ListServiceAccountKeysResponse), nil
}

func (f *fakeIAM) GetServiceAccountKey(ctx context.Context, req *iampb.GetServiceAccountKeyRequest) (*iampb.ServiceAccountKey, error) {
	glog.Infof("GetServiceAccountKeyReq: %v", req)
	name := req.Name
	for _, a := range f.keys {
		if a.Name == name {
			resp := a
			glog.Infof("GetServiceAccountKey: %v", resp)
			return proto.Clone(resp).(*iampb.ServiceAccountKey), nil
		}
	}
	return nil, status.Errorf(codes.NotFound, "service account key with name %q not found", name)
}

func (f *fakeIAM) CreateServiceAccountKey(ctx context.Context, req *iampb.CreateServiceAccountKeyRequest) (*iampb.ServiceAccountKey, error) {
	glog.Infof("CreateServiceAccountKeyReq: %v", req)
	account := req.Name
	id := fmt.Sprintf("fake-key-id-%v", len(f.keys))
	name := fmt.Sprintf("%v/keys/%v", account, id)
	for _, a := range f.keys {
		if a.Name == name {
			glog.Infof("CreateServiceAccountKeyResp AlreadyExists: %v", a)
			return nil, status.Errorf(codes.AlreadyExists, "service account with name %q already exists", name)
		}
	}
	a := &iampb.ServiceAccountKey{
		Name:            name,
		PrivateKeyType:  iampb.ServiceAccountPrivateKeyType_TYPE_GOOGLE_CREDENTIALS_FILE,
		KeyAlgorithm:    iampb.ServiceAccountKeyAlgorithm_KEY_ALG_RSA_2048,
		PrivateKeyData:  []byte(name + "/fake-private-key"),
		PublicKeyData:   []byte(name + "/fake-public-key"),
		ValidAfterTime:  Timestamp(time.Now()),
		ValidBeforeTime: Timestamp(time.Now().Add(24 * time.Hour)),
	}
	f.keys = append(f.keys, a)
	glog.Infof("CreateServiceAccountKeyResp: %v", a)
	return a, nil
}

func (f *fakeIAM) DeleteServiceAccountKey(ctx context.Context, req *iampb.DeleteServiceAccountKeyRequest) (*epb.Empty, error) {
	glog.Infof("DeleteServiceAccountKeyReq: %v", req)
	name := req.Name
	var updated []*iampb.ServiceAccountKey
	for _, a := range f.keys {
		if a.Name != name {
			updated = append(updated, a)
		}
	}
	f.keys = updated
	return &epb.Empty{}, nil
}

type fakeIAMCreds struct {
	count  int
	tokens []*iamcredscpb.GenerateAccessTokenResponse
	iamcredsgrpcpb.IAMCredentialsServer
}

func (f *fakeIAMCreds) GenerateAccessToken(ctx context.Context, req *iamcredscpb.GenerateAccessTokenRequest) (*iamcredscpb.GenerateAccessTokenResponse, error) {
	glog.Infof("GenerateAccessTokenReq: %v", req)
	exp, _ := ptypes.TimestampProto(time.Now().Add(time.Hour))
	f.count++
	resp := &iamcredscpb.GenerateAccessTokenResponse{AccessToken: fmt.Sprintf("token-%v", f.count), ExpireTime: exp}
	f.tokens = append(f.tokens, resp)
	glog.Infof("GenerateAccessTokenResp: %v", resp)
	return proto.Clone(resp).(*iamcredscpb.GenerateAccessTokenResponse), nil
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

// HashProto computes a hash of a proto.
func HashProto(msg proto.Message) []byte {
	h := sha256.New()
	io.WriteString(h, msg.String())
	return h.Sum(nil)
}
