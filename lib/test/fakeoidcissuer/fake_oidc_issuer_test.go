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

package fakeoidcissuer

import (
	"context"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/coreos/go-oidc"
)

func TestServer(t *testing.T) {
	const (
		issuerURL = "https://example.com/oidc"
		aud = "test"
	)
	now := time.Now().Unix()

	server, err := New(issuerURL)
	if err != nil {
		t.Fatalf("fakeoidcissuer.New(issuerURL) failed: %v", err)
	}

	claim := jwt.StandardClaims{
		Issuer:    issuerURL,
		IssuedAt:  now - 10000,
		ExpiresAt: now + 10000,
		Audience:  aud,
	}
	header := map[string]string{"kid": "kid"}

	jwt, err := server.Sign(header, claim)
	if err != nil {
		t.Fatalf("server.Sign(header, claim) failed: %v", err)
	}

	ctx := server.ContextWithClient(context.Background())
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		t.Fatalf("oidc.NewProvider(ctx, issuerURL) failed: %v", err)
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: aud})

	if _, err = verifier.Verify(ctx, jwt); err != nil {
		t.Fatalf("verifier.Verify(ctx, jwt) failed: %v", err)
	}
}
