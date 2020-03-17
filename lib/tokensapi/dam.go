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

package tokensapi

import (
	"context"
	"regexp"

	glog "github.com/golang/glog" /* copybara-comment */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/saw" /* copybara-comment: saw */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	epb "github.com/golang/protobuf/ptypes/empty" /* copybara-comment */
	dampb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
	tpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/tokens/v1" /* copybara-comment: go_proto */
)

// DAMTokens is implments the tokens API for DAM.
// Currently support GCP tokens.
type DAMTokens struct {
	store storage.Store
	saw   *saw.AccountWarehouse
}

// NewDAMTokens creates a new DAMTokens.
func NewDAMTokens(store storage.Store, saw *saw.AccountWarehouse) *DAMTokens {
	return &DAMTokens{store: store, saw: saw}
}

// GetToken returns the token.
func (s *DAMTokens) GetToken(_ context.Context, req *tpb.GetTokenRequest) (*tpb.Token, error) {
	glog.Info("GetTokenRequest")
	return nil, status.Error(codes.Unimplemented, "get is not implemented")
}

// DeleteToken revokes a token.
func (s *DAMTokens) DeleteToken(ctx context.Context, req *tpb.DeleteTokenRequest) (*epb.Empty, error) {
	glog.Info("DeleteTokenRequest")
	name := req.GetName()
	ids := resourceRE.FindStringSubmatch(name)
	if len(ids) < 3 {
		return nil, status.Errorf(codes.InvalidArgument, "invalud name: %v", name)
	}

	project, err := saProject(s.store, storage.DefaultRealm)
	if err != nil {
		return nil, err
	}
	ids[0] = project

	// TODO: demux based on the platform from which the token is from.

	if err := s.GCPDeleteToken(ctx, ids); err != nil {
		return nil, err
	}

	return &epb.Empty{}, nil
}

// ListTokens lists the tokens.
func (s *DAMTokens) ListTokens(ctx context.Context, req *tpb.ListTokensRequest) (*tpb.ListTokensResponse, error) {
	glog.Infof("ListTokensRequest")
	parent := req.GetParent()
	ids := parentRE.FindStringSubmatch(parent)
	if len(ids) < 2 {
		return nil, status.Errorf(codes.InvalidArgument, "invalud parent: %v", parent)
	}

	project, err := saProject(s.store, storage.DefaultRealm)
	if err != nil {
		return nil, err
	}
	ids[0] = project

	tokens, err := s.GCPListTokens(ctx, ids)
	if err != nil {
		return nil, err
	}

	// TODO: mux based on the platform from which the token is from.

	return &tpb.ListTokensResponse{Tokens: tokens}, nil
}

var (
	parentRE   = regexp.MustCompile("^users/([^/]*)$")
	resourceRE = regexp.MustCompile("^users/([^/]*)/tokens/([^/]*)$")
)

func saProject(store storage.Store, realm string) (string, error) {
	cfg := &dampb.DamConfig{}
	if err := store.Read(storage.ConfigDatatype, realm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, cfg); err != nil {
		return "", err
	}
	return cfg.Options.GcpServiceAccountProject, nil
}
