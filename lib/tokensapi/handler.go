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
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/gorilla/mux" /* copybara-comment */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/handlerfactory" /* copybara-comment: handlerfactory */

	epb "github.com/golang/protobuf/ptypes/empty" /* copybara-comment */
	tpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/tokens/v1" /* copybara-comment: go_proto */
)

var (
	// tokenIDRE token_id part is base64 url encoded.
	// base64 url encoding see: https://tools.ietf.org/html/rfc4648#section-5
	tokenIDRE = regexp.MustCompile(`^(gcp|hydra):[0-9a-zA-Z-_]*$`)
)

// Token is used in TokenProvider below.
type Token struct {
	User        string
	RawTokenID  string
	TokenPrefix string
	IssuedAt    int64
	ExpiresAt   int64
}

// TokenProvider includes methods for token management.
type TokenProvider interface {
	ListTokens(ctx context.Context, user string) ([]*Token, error)
	DeleteToken(ctx context.Context, user, tokenID string) error
	TokenPrefix() string
}

func encodeTokenName(user, prefix, tokenID string) string {
	return fmt.Sprintf("users/%s/tokens/%s:%s", user, prefix, base64.RawURLEncoding.EncodeToString([]byte(tokenID)))
}

// decodeTokenName splits token_id to token prefix and original tokne_id
func decodeTokenName(tokenID string) (string, string, error) {
	ss := strings.Split(tokenID, ":")
	if len(ss) != 2 {
		return "", "", status.Errorf(codes.InvalidArgument, "token format invalid")
	}
	b, err := base64.RawURLEncoding.DecodeString(ss[1])
	if err != nil {
		return "", "", status.Errorf(codes.InvalidArgument, "token decode failed: %v", err)
	}
	return ss[0], string(b), nil
}

// ListTokensFactory creates a http handler for "/(identity|dam)/v1alpha/users/{user}/tokens"
// TODO should support filter parameters.
func ListTokensFactory(tokensPath string, providers []TokenProvider) *handlerfactory.Options {
	return &handlerfactory.Options{
		TypeName:            "token",
		PathPrefix:          tokensPath,
		HasNamedIdentifiers: false,
		Service: func() handlerfactory.Service {
			return &listTokensHandler{providers: providers}
		},
	}
}

type listTokensHandler struct {
	handlerfactory.Empty
	providers []TokenProvider
}

func (s *listTokensHandler) Get(r *http.Request, name string) (proto.Message, error) {
	userID := mux.Vars(r)["user"]

	resp := &tpb.ListTokensResponse{}
	for _, p := range s.providers {
		l, err := p.ListTokens(r.Context(), userID)
		if err != nil {
			return nil, err
		}
		for _, t := range l {
			resp.Tokens = append(resp.Tokens, &tpb.Token{
				Name:      encodeTokenName(t.User, t.TokenPrefix, t.RawTokenID),
				IssuedAt:  t.IssuedAt,
				ExpiresAt: t.ExpiresAt,
			})
		}
	}

	return resp, nil
}

// DeleteTokenFactory creates a http handler for "/(identity|dam)/v1alpha/users/{user}/tokens/{token_id}"
func DeleteTokenFactory(tokenPath string, providers []TokenProvider) *handlerfactory.Options {
	return &handlerfactory.Options{
		TypeName:            "token",
		PathPrefix:          tokenPath,
		HasNamedIdentifiers: false,
		NameChecker: map[string]*regexp.Regexp{
			"token_id": tokenIDRE,
		},
		Service: func() handlerfactory.Service {
			return &deleteTokenHandler{
				providers: providers,
			}
		},
	}
}

type deleteTokenHandler struct {
	handlerfactory.Empty
	providers []TokenProvider
}

func (s *deleteTokenHandler) Remove(r *http.Request, name string) (proto.Message, error) {
	userID := mux.Vars(r)["user"]
	tID := mux.Vars(r)["token_id"]

	prefix, tokenID, err := decodeTokenName(tID)
	if err != nil {
		return nil, err
	}

	found := false
	for _, p := range s.providers {
		if p.TokenPrefix() == prefix {
			found = true
			err := p.DeleteToken(r.Context(), userID, tokenID)
			if err != nil {
				return nil, err
			}
		}
	}

	if !found {
		return nil, status.Errorf(codes.InvalidArgument, "unknown token platform: %s", prefix)
	}

	return &epb.Empty{}, nil
}
