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

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/adapter" /* copybara-comment: adapter */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/saw" /* copybara-comment: saw */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/timeutil" /* copybara-comment: timeutil */
)

// GCP tokens management, implments TokenProvider interface.
type GCP struct {
	saProject     string
	defaultBroker string
	saw           *saw.AccountWarehouse
}

// NewGCPTokenManager creates a GCP object
func NewGCPTokenManager(saProject, defaultBroker string, saw *saw.AccountWarehouse) *GCP {
	return &GCP{
		saProject:     saProject,
		defaultBroker: defaultBroker,
		saw:           saw,
	}
}

// ListTokens lists the tokens.
func (s *GCP) ListTokens(ctx context.Context, user string, store storage.Store, tx storage.Tx) ([]*Token, error) {
	userID := ga4gh.TokenUserID(&ga4gh.Identity{Subject: user, Issuer: s.defaultBroker}, adapter.SawMaxUserIDLength)
	vs, err := s.saw.ListTokenMetadata(ctx, s.saProject, userID)
	if err != nil {
		// TODO: Should pass error from GRPC call to here for better error code.
		return nil, status.Errorf(codes.Unavailable, "list gcp tokens failed: %v", err)
	}
	var tokens []*Token
	for _, v := range vs {
		t := &Token{
			User:        user,
			RawTokenID:  v.Name,
			TokenPrefix: s.TokenPrefix(),
			IssuedAt:    timeutil.ParseRFC3339(v.IssuedAt).Unix(),
			ExpiresAt:   timeutil.ParseRFC3339(v.Expires).Unix(),
			Platform:    s.TokenPrefix(),
		}
		tokens = append(tokens, t)
	}
	return tokens, nil
}

// DeleteToken revokes a token.
func (s *GCP) DeleteToken(ctx context.Context, user, tokenID string, store storage.Store, tx storage.Tx) error {
	userID := ga4gh.TokenUserID(&ga4gh.Identity{Subject: user, Issuer: s.defaultBroker}, adapter.SawMaxUserIDLength)
	if err := s.saw.DeleteTokens(ctx, s.saProject, userID, []string{tokenID}); err != nil {
		// TODO: Should pass error from GRPC call to here for better error code.
		return status.Errorf(codes.Unavailable, "delete gcp token failed: %v", err)
	}
	return nil
}

// TokenPrefix of GCP provided tokens.
func (s *GCP) TokenPrefix() string {
	return "gcp"
}
