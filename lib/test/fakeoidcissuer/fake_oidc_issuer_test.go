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
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/playground"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/translator"
)

// TODO: consider moving this to be lib/persona/broker_test.go
func TestServer(t *testing.T) {
	const (
		issuerURL = "https://example.com/oidc"
		aud       = "test"
	)
	now := time.Now().Unix()

	server, err := New(issuerURL, &testkeys.PersonaBrokerKey, "dam", "testdata/config")
	if err != nil {
		t.Fatalf("fakeoidcissuer.New(issuerURL) failed: %v", err)
	}

	claim := jwt.StandardClaims{
		Issuer:    issuerURL,
		IssuedAt:  now - 10000,
		ExpiresAt: now + 10000,
		Audience:  aud,
	}
	header := map[string]string{"kid": testkeys.PersonaBrokerKey.ID}

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

	pname := "dr_joe_elixir"
	persona, ok := server.Config().TestPersonas[pname]
	if !ok {
		t.Fatalf("test persona %q not found in config", pname)
	}
	acTok, sub, err := playground.PersonaAccessToken(pname, issuerURL, aud, persona)
	if err != nil {
		t.Fatalf("playground.PersonaAccessToken(%q, %q, _) failed: %v", pname, issuerURL, err)
	}
	user := &ga4gh.Identity{
		Issuer:  issuerURL,
		Subject: sub,
	}
	trans, err := translator.NewOIDCIdentityTranslator(ctx, issuerURL, "")
	if err != nil {
		t.Fatalf("translator.NewOIDCIdentityTranslator(ctx, %q, _) failed: %v", issuerURL, err)
	}
	id, err := translator.FetchUserinfoClaims(ctx, string(acTok), user, trans)
	if err != nil {
		t.Fatalf("translator.FetchUserinfoClaims(ctx, tok, user, trans) failed: %v", err)
	}
	if len(id.VisaJWTs) == 0 {
		t.Errorf("id.VisaJWTs: wanted more than zero, got none")
	}
}
