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

	"github.com/coreos/go-oidc"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/common"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh"
)

const (
	elixirIssuer = "https://login.elixir-czech.org/oidc/"
)

// ElixirTranslator is a ga4gh.Translator that converts ELIXIR identities into GA4GH identities.
type ElixirTranslator struct {
	verifier *oidc.IDTokenVerifier
}

// NewElixirTranslator creates a new ElixirTranslator with the provided OIDC client ID. If the
// tokens passed to this translator do not have an audience claim with a value equal to the
// clientID value then they will be rejected.
func NewElixirTranslator(ctx context.Context, clientID string) (*ElixirTranslator, error) {
	v, err := common.GetOIDCTokenVerifier(ctx, clientID, elixirIssuer)
	if err != nil {
		return nil, err
	}
	return &ElixirTranslator{verifier: v}, nil
}

// TranslateToken implements the ga4gh.Translator interface.
func (s *ElixirTranslator) TranslateToken(ctx context.Context, auth string) (*ga4gh.Identity, error) {
	if _, err := s.verifier.Verify(ctx, auth); err != nil {
		return nil, fmt.Errorf("verifying token: %v", err)
	}
	return s.translateToken(auth)
}

func (s *ElixirTranslator) translateToken(auth string) (*ga4gh.Identity, error) {
	id, err := common.ConvertTokenToIdentityUnsafe(auth)
	if err != nil {
		return nil, fmt.Errorf("inspecting token: %v", err)
	}
	return id, nil
}
