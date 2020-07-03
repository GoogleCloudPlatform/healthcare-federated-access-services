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

package adapter

import (
	"context"
	"fmt"
	"time"

	"github.com/pborman/uuid" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/kms" /* copybara-comment: kms */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/srcutil" /* copybara-comment: srcutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/timeutil" /* copybara-comment: timeutil */

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
)

const (
	gatekeeperName        = "gatekeeper"
	gatekeeperAdapterName = "token:jwt:gatekeeper"
	gatekeeperPlatform    = "dam"
	secretsName           = "secrets"
	mainID                = "main"
	keyID                 = "kid"
)

// GatekeeperToken is the token format that is minted here.
type GatekeeperToken struct {
	*ga4gh.StdClaims
	Scopes []string `json:"scopes,omitempty"`
}

// GatekeeperAdapter generates downstream access tokens.
type GatekeeperAdapter struct {
	desc   map[string]*pb.ServiceDescriptor
	signer kms.Signer
}

// NewGatekeeperAdapter creates a GatekeeperAdapter.
func NewGatekeeperAdapter(signer kms.Signer) (ServiceAdapter, error) {
	var msg pb.ServicesResponse
	path := adapterFilePath(gatekeeperName)
	if err := srcutil.LoadProto(path, &msg); err != nil {
		return nil, fmt.Errorf("reading %q service descriptors from path %q: %v", aggregatorName, path, err)
	}

	return &GatekeeperAdapter{
		desc:   msg.Services,
		signer: signer,
	}, nil
}

// Name returns the name identifier of the adapter as used in configurations.
func (a *GatekeeperAdapter) Name() string {
	return gatekeeperAdapterName
}

// Platform returns the name identifier of the platform on which this adapter operates.
func (a *GatekeeperAdapter) Platform() string {
	return gatekeeperPlatform
}

// Descriptors returns a map of ServiceAdapter descriptors.
func (a *GatekeeperAdapter) Descriptors() map[string]*pb.ServiceDescriptor {
	return a.desc
}

// IsAggregator returns true if this adapter requires TokenAction.Aggregates.
func (a *GatekeeperAdapter) IsAggregator() bool {
	return false
}

// CheckConfig validates that a new configuration is compatible with this adapter.
func (a *GatekeeperAdapter) CheckConfig(templateName string, template *pb.ServiceTemplate, resName, viewName string, view *pb.View, cfg *pb.DamConfig, adapters *ServiceAdapters) (string, error) {
	if view != nil && len(view.Items) > 1 {
		return httputils.StatusPath("resources", resName, "views", viewName, "items"), fmt.Errorf("view %q has more than one target item defined", viewName)
	}
	return "", nil
}

// MintToken has the adapter mint a token.
func (a *GatekeeperAdapter) MintToken(ctx context.Context, input *Action) (*MintTokenResult, error) {
	if input.MaxTTL > 0 && input.TTL > input.MaxTTL {
		return nil, fmt.Errorf("minting gatekeeper token: TTL of %q exceeds max TTL of %q", timeutil.TTLString(input.TTL), timeutil.TTLString(input.MaxTTL))
	}

	now := time.Now()
	var auds []string
	// TODO: support standard audience formats instead of space-delimited.
	for _, item := range input.View.Items {
		if item.Args == nil {
			continue
		}
		if a, ok := item.Args["aud"]; ok {
			auds = append(auds, a)
		}
	}

	scopes := []string{}
	arg, ok := input.ServiceRole.ServiceArgs["scopes"]
	if ok {
		scopes = arg.Values
	}

	claims := &GatekeeperToken{
		StdClaims: &ga4gh.StdClaims{
			Issuer:    input.Issuer,
			Subject:   input.Identity.Subject,
			Audience:  auds,
			ExpiresAt: now.Add(input.TTL).Unix(),
			NotBefore: now.Add(-1 * time.Minute).Unix(),
			IssuedAt:  now.Unix(),
			ID:        uuid.New(),
		},
		Scopes: scopes,
	}

	token, err := a.signer.SignJWT(ctx, claims, nil)
	if err != nil {
		return nil, fmt.Errorf("minting gatekeeper token: sign token failed: %v", err)
	}

	return &MintTokenResult{
		Credentials: map[string]string{
			"account":      input.Identity.Subject,
			"access_token": token,
		},
		TokenFormat: "base64",
	}, nil
}
