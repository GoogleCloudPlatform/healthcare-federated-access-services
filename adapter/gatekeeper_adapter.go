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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/clouds"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/common"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/storage"

	pb "google3/third_party/hcls_federated_access/dam/api/v1/go_proto"
)

const (
	gatekeeperName        = "gatekeeper"
	gatekeeperAdapterName = "token:jwt:gatekeeper"
	secretsName           = "secrets"
	mainID                = "main"
	keyID                 = "kid"
)

// GatekeeperToken is the token format that is minted here.
type GatekeeperToken struct {
	*jwt.StandardClaims
	AuthorizedParty string   `json:"azp,omitempty"`
	Scopes          []string `json:"scopes,omitempty"`
}

// GatekeeperAdapter generates downstream access tokens.
type GatekeeperAdapter struct {
	desc       *pb.TargetAdapter
	privateKey string
}

// NewGatekeeperAdapter creates a GatekeeperAdapter.
func NewGatekeeperAdapter(store storage.Store, warehouse clouds.ResourceTokenCreator, secrets *pb.DamSecrets, adapters *TargetAdapters) (Adapter, error) {
	var desc pb.TargetAdapter
	if err := store.Read(AdapterDataType, storage.DefaultRealm, storage.DefaultUser, gatekeeperName, storage.LatestRev, &desc); err != nil {
		return nil, fmt.Errorf("reading %q descriptor: %v", gatekeeperName, err)
	}
	keys := secrets.GetGatekeeperTokenKeys()
	if keys == nil {
		return nil, fmt.Errorf("gatekeeper token keys not found")
	}

	return &GatekeeperAdapter{
		desc:       &desc,
		privateKey: keys.PrivateKey,
	}, nil
}

// Name returns the name identifier of the adapter as used in configurations.
func (a *GatekeeperAdapter) Name() string {
	return gatekeeperAdapterName
}

// Descriptor returns a TargetAdapter descriptor.
func (a *GatekeeperAdapter) Descriptor() *pb.TargetAdapter {
	return a.desc
}

// IsAggregator returns true if this adapter requires TokenAction.Aggregates.
func (a *GatekeeperAdapter) IsAggregator() bool {
	return false
}

// CheckConfig validates that a new configuration is compatible with this adapter.
func (a *GatekeeperAdapter) CheckConfig(templateName string, template *pb.ServiceTemplate, viewName string, view *pb.View, cfg *pb.DamConfig, adapters *TargetAdapters) error {
	if view != nil && len(view.Items) > 1 {
		return fmt.Errorf("view %q has more than one target item defined", viewName)
	}
	return nil
}

// MintToken has the adapter mint a token and return <account>, <token>, error.
func (a *GatekeeperAdapter) MintToken(input *Action) (string, string, error) {
	if input.MaxTTL > 0 && input.TTL > input.MaxTTL {
		return "", "", fmt.Errorf("minting gatekeeper token: TTL of %q exceeds max TTL of %q", common.TtlString(input.TTL), common.TtlString(input.MaxTTL))
	}
	block, _ := pem.Decode([]byte(a.privateKey))
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", "", fmt.Errorf("parsing private key: %v", err)
	}
	now := time.Now()

	claims := &GatekeeperToken{
		StandardClaims: &jwt.StandardClaims{
			Issuer:    input.Issuer,
			Subject:   input.Identity.Subject,
			Audience:  input.View.Aud,
			ExpiresAt: now.Add(input.TTL).Unix(),
			NotBefore: now.Add(-1 * time.Minute).Unix(),
			IssuedAt:  now.Unix(),
			Id:        common.GenerateGUID(),
		},
		Scopes: input.ServiceRole.TargetScopes,
	}

	jot := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// TODO: should set key id properly and sync with JWKS.
	jot.Header[keyID] = keyID
	token, err := jot.SignedString(priv)
	if err != nil {
		return "", "", err
	}
	return input.Identity.Subject, token, nil
}
