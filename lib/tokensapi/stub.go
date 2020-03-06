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

	glog "github.com/golang/glog" /* copybara-comment */
	epb "github.com/golang/protobuf/ptypes/empty" /* copybara-comment */
	tpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/tokens/v1" /* copybara-comment: go_proto */
)

// StubTokens is a stub implementation.
type StubTokens struct {
	Token *tpb.Token
}

// GetToken returns the token.
func (s *StubTokens) GetToken(_ context.Context, req *tpb.GetTokenRequest) (*tpb.Token, error) {
	glog.Infof("GetToken %v", req)
	return s.Token, nil
}

// DeleteToken revokes a token.
func (s *StubTokens) DeleteToken(_ context.Context, req *tpb.DeleteTokenRequest) (*epb.Empty, error) {
	glog.Infof("DeleteToken %v", req)
	return &epb.Empty{}, nil
}

// ListTokens lists the tokens.
func (s *StubTokens) ListTokens(_ context.Context, req *tpb.ListTokensRequest) (*tpb.ListTokensResponse, error) {
	glog.Infof("ListTokens %v", req)
	return &tpb.ListTokensResponse{Tokens: []*tpb.Token{s.Token}}, nil
}

// FakeToken is a fake token.
// TODO: move these fakes to test file once implemented.
var FakeToken = &tpb.Token{
	Name:      "fake-token",
	Issuer:    "fake-issuer",
	Audience:  "fake-audience",
	Subject:   "fake-subject",
	IssuedAt:  1573850929,
	ExpiresAt: 1573847329,
	Scope:     "fake-scope",
	Client: &tpb.Client{
		Id:          "fake-client-id",
		Name:        "fake-client-name",
		Description: "fake-client-description",
	},
	Target: "fake-target",
	Metadata: map[string]string{
		"client_desc": "fake-client-ui-description",
	},
	Type: "fake-type",
}

const fakeTokenJSON = `{
  "aud": "fake-audience",
  "client": {
    "description": "fake-client-description",
    "id": "fake-client-id",
    "name": "fake-client-name"
  },
 	"exp": "1573847329",
 	"iat": "1573850929",
	"iss": "fake-issuer",
  "metadata": {
    "client_desc": "fake-client-ui-description"
  },
  "name": "fake-token",
  "scope": "fake-scope",
	"sub": "fake-subject",
  "target": "fake-target",
	"type": "fake-type"
}`
