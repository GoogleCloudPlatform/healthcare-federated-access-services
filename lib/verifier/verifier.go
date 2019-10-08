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

// Package verifier provides a token verifier.
package verifier

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh"
)

// Verifier is used to verify tokens.
type Verifier struct {
	clientID string
}

// New creates a new Verifier.
func New(clientID string) *Verifier {
	return &Verifier{clientID: clientID}
}

// Verify verifies the provided token.
func (v *Verifier) Verify(ctx context.Context, token string) error {
	d, err := ga4gh.NewStdClaimsFromJWT(token)
	if err != nil {
		return fmt.Errorf("ExtractIssuer(token) failed: %v", err)
	}
	issuer := d.Issuer
	op, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return fmt.Errorf("oidc.NewProvider(_,%v) failed: %v", issuer, err)
	}
	ov := op.Verifier(&oidc.Config{ClientID: v.clientID})

	if _, err := ov.Verify(ctx, token); err != nil {
		return err
	}
	return nil
}

var (
	_ ga4gh.JWTVerifier = New("").Verify
)
