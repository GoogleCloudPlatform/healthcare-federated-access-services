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

// Package fakeiam provides a fake implementation for IAM services:
// IAM Admin
// IAM Credendtials
package fakeiam

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"
	"time"

	glog "github.com/golang/glog" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
	"github.com/golang/protobuf/ptypes" /* copybara-comment */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/pborman/uuid" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/timeutil" /* copybara-comment: timeutil */

	iamgrpcpb "google.golang.org/genproto/googleapis/iam/admin/v1" /* copybara-comment: iam_go_grpc */
	iampb "google.golang.org/genproto/googleapis/iam/admin/v1" /* copybara-comment: iam_go_proto */
	iamcredscpb "google.golang.org/genproto/googleapis/iam/credentials/v1" /* copybara-comment: common_go_proto */
	iamcredsgrpcpb "google.golang.org/genproto/googleapis/iam/credentials/v1" /* copybara-comment: iamcredentials_go_grpc */
	epb "github.com/golang/protobuf/ptypes/empty" /* copybara-comment */
)

// Admin is a fake implementation of IAM Admin service.
type Admin struct {
	State chan AdminState

	iamgrpcpb.IAMServer
}

// AdminState stores the data of Admin.
type AdminState struct {
	Accounts []*iampb.ServiceAccount
	Keys     []*iampb.ServiceAccountKey
}

// NewAdmin creates a new fake Admin server.
func NewAdmin() *Admin {
	s := &Admin{State: make(chan AdminState, 1)}
	s.State <- AdminState{}
	return s
}

func (f *Admin) ListServiceAccounts(ctx context.Context, req *iampb.ListServiceAccountsRequest) (*iampb.ListServiceAccountsResponse, error) {
	glog.Infof("ListServiceAccountsReq: %v", req)
	state := <-f.State
	defer func() { f.State <- state }()
	resp := &iampb.ListServiceAccountsResponse{Accounts: state.Accounts}
	glog.Infof("ListServiceAccountsResp: %v", resp)
	return proto.Clone(resp).(*iampb.ListServiceAccountsResponse), nil
}

func (f *Admin) GetServiceAccount(ctx context.Context, req *iampb.GetServiceAccountRequest) (*iampb.ServiceAccount, error) {
	glog.Infof("GetServiceAccountReq: %v", req)
	state := <-f.State
	defer func() { f.State <- state }()
	name := req.Name
	for _, a := range state.Accounts {
		if a.Name == name {
			glog.Infof("GetServiceAccountResp: %v", a)
			return a, nil
		}
	}
	return nil, status.Errorf(codes.NotFound, "service account with name %q not found", name)
}

func (f *Admin) CreateServiceAccount(ctx context.Context, req *iampb.CreateServiceAccountRequest) (*iampb.ServiceAccount, error) {
	glog.Infof("CreateServiceAccountReq: %v", req)
	state := <-f.State
	defer func() { f.State <- state }()

	proj := strings.Split(req.Name, "/")[1]
	email := fmt.Sprintf("%v@%v.iam.gserviceaccount.com", req.AccountId, proj)
	name := fmt.Sprintf("projects/%v/serviceAccounts/%v", proj, email)
	guid := uuid.New()
	for _, a := range state.Accounts {
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
	state.Accounts = append(state.Accounts, a)

	glog.Infof("CreateServiceAccountResp: %v", a)
	return a, nil
}

func (f *Admin) DeleteServiceAccount(ctx context.Context, req *iampb.DeleteServiceAccountRequest) (*epb.Empty, error) {
	glog.Infof("DeleteServiceAccountReq: %v", req)
	state := <-f.State
	defer func() { f.State <- state }()
	name := req.Name
	var updated []*iampb.ServiceAccount
	for _, a := range state.Accounts {
		if a.Name != name {
			updated = append(updated, a)
		}
	}
	state.Accounts = updated
	return &epb.Empty{}, nil
}

func (f *Admin) ListServiceAccountKeys(ctx context.Context, req *iampb.ListServiceAccountKeysRequest) (*iampb.ListServiceAccountKeysResponse, error) {
	glog.Infof("ListServiceAccountKeysReq: %v", req)
	state := <-f.State
	defer func() { f.State <- state }()
	resp := &iampb.ListServiceAccountKeysResponse{Keys: state.Keys}
	glog.Infof("ListServiceAccountKeysResp: %v", resp)
	return proto.Clone(resp).(*iampb.ListServiceAccountKeysResponse), nil
}

func (f *Admin) GetServiceAccountKey(ctx context.Context, req *iampb.GetServiceAccountKeyRequest) (*iampb.ServiceAccountKey, error) {
	glog.Infof("GetServiceAccountKeyReq: %v", req)
	state := <-f.State
	defer func() { f.State <- state }()
	name := req.Name
	for _, a := range state.Keys {
		if a.Name == name {
			resp := a
			glog.Infof("GetServiceAccountKey: %v", resp)
			return proto.Clone(resp).(*iampb.ServiceAccountKey), nil
		}
	}
	return nil, status.Errorf(codes.NotFound, "service account key with name %q not found", name)
}

func (f *Admin) CreateServiceAccountKey(ctx context.Context, req *iampb.CreateServiceAccountKeyRequest) (*iampb.ServiceAccountKey, error) {
	glog.Infof("CreateServiceAccountKeyReq: %v", req)
	state := <-f.State
	defer func() { f.State <- state }()
	account := req.Name
	id := fmt.Sprintf("fake-key-id-%v", len(state.Keys))
	name := fmt.Sprintf("%v/keys/%v", account, id)
	for _, a := range state.Keys {
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
		ValidAfterTime:  timeutil.TimestampProto(time.Now()),
		ValidBeforeTime: timeutil.TimestampProto(time.Now().Add(24 * time.Hour)),
	}
	state.Keys = append(state.Keys, a)
	glog.Infof("CreateServiceAccountKeyResp: %v", a)
	return a, nil
}

func (f *Admin) DeleteServiceAccountKey(ctx context.Context, req *iampb.DeleteServiceAccountKeyRequest) (*epb.Empty, error) {
	glog.Infof("DeleteServiceAccountKeyReq: %v", req)
	state := <-f.State
	defer func() { f.State <- state }()
	name := req.Name
	var updated []*iampb.ServiceAccountKey
	for _, a := range state.Keys {
		if a.Name != name {
			updated = append(updated, a)
		}
	}
	state.Keys = updated
	return &epb.Empty{}, nil
}

// Creds is a fake implementation of IAMCredentialsServer.
type Creds struct {
	State chan CredsState
	iamcredsgrpcpb.IAMCredentialsServer
}

// CredsState contains the state of the Creds
type CredsState struct {
	// Tokens is the list of tokens issued.
	Tokens []*iamcredscpb.GenerateAccessTokenResponse
}

// NewCreds creates a new Creds server.
func NewCreds() *Creds {
	s := &Creds{State: make(chan CredsState, 1)}
	s.State <- CredsState{}
	return s
}

func (f *Creds) GenerateAccessToken(ctx context.Context, req *iamcredscpb.GenerateAccessTokenRequest) (*iamcredscpb.GenerateAccessTokenResponse, error) {
	glog.Infof("GenerateAccessTokenReq: %v", req)
	state := <-f.State
	defer func() { f.State <- state }()
	d := timeutil.Duration(req.GetLifetime())
	if d == 0 {
		d = time.Hour
	}
	if d > time.Hour {
		return nil, status.Errorf(codes.InvalidArgument, "token lifetime %v exceeds the max allowed lifetime of 1 hour", d)
	}
	exp, _ := ptypes.TimestampProto(time.Now().Add(d))
	token := fmt.Sprintf("%v/token-%v", req.GetName(), len(state.Tokens))
	resp := &iamcredscpb.GenerateAccessTokenResponse{AccessToken: token, ExpireTime: exp}
	state.Tokens = append(state.Tokens, resp)
	glog.Infof("GenerateAccessTokenResp: %v", resp)
	return proto.Clone(resp).(*iamcredscpb.GenerateAccessTokenResponse), nil
}

// HashProto computes a hash of a proto.
func HashProto(msg proto.Message) []byte {
	h := sha256.New()
	io.WriteString(h, msg.String())
	return h.Sum(nil)
}
