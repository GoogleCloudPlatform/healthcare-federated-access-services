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

package translator

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common" /* copybara-comment: common */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
)

// OIDCIdentityTranslator verifies signatures for tokens returned by an OIDC endpoint and in the
// standard GA4GH identity format.
type OIDCIdentityTranslator struct {
	verifier *oidc.IDTokenVerifier
}

// NewOIDCIdentityTranslator creates a new OIDCIdentityTranslator with the provided issuer and
// client ID.
func NewOIDCIdentityTranslator(ctx context.Context, issuer, clientID string) (*OIDCIdentityTranslator, error) {
	v, err := common.GetOIDCTokenVerifier(ctx, clientID, issuer)
	if err != nil {
		return nil, err
	}
	return &OIDCIdentityTranslator{verifier: v}, nil
}

// TranslateToken implements the ga4gh.Translator interface.
func (s *OIDCIdentityTranslator) TranslateToken(ctx context.Context, auth string) (*ga4gh.Identity, error) {
	if _, err := s.verifier.Verify(ctx, auth); err != nil {
		return nil, fmt.Errorf("verifying token: %v", err)
	}
	return s.translateToken(auth)
}

func (s *OIDCIdentityTranslator) translateToken(auth string) (*ga4gh.Identity, error) {
	id, err := common.ConvertTokenToIdentityUnsafe(auth)
	if err != nil {
		return nil, fmt.Errorf("inspecting token: %v", err)
	}
	return id, nil
}
