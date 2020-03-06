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

	epb "github.com/golang/protobuf/ptypes/empty" /* copybara-comment */
	tpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/tokens/v1" /* copybara-comment: go_proto */
)

// DAMTokens is implments the tokens API for DAM.
// Currently support GCP tokens.
type DAMTokens struct {
	saw *saw.AccountWarehouse
}

// NewDAMTokens creates a new DAMTokens.
func NewDAMTokens(saw *saw.AccountWarehouse) *DAMTokens {
	return &DAMTokens{saw: saw}
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

	// TODO: demux based on the platform from which the token is from.

	err := s.GCPDeleteToken(ctx, ids)
	if err != nil {
		return nil, err
	}

	return &epb.Empty{}, nil
}

// ListTokens lists the tokens.
func (s *DAMTokens) ListTokens(ctx context.Context, req *tpb.ListTokensRequest) (*tpb.ListTokensResponse, error) {
	glog.Infof("ListTokensRequest")
	parent := req.GetParent()
	ids := parentRE.FindStringSubmatch(parent)
	if len(ids) < 3 {
		return nil, status.Errorf(codes.InvalidArgument, "invalud parent: %v", parent)
	}

	tokens, err := s.GCPListTokens(ctx, ids)
	if err != nil {
		return nil, err
	}

	// TODO: mux based on the platform from which the token is from.

	return &tpb.ListTokensResponse{Tokens: tokens}, nil
}

var (
	parentRE   = regexp.MustCompile("^projects/([^/]*)/users/([^/]*)$")
	resourceRE = regexp.MustCompile("^projects/([^/]*)/users/([^/]*)/tokens/([^/]*)$")
)
