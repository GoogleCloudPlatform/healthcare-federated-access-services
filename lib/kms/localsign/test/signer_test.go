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

// Package localsign_test test localsign package
package localsign_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"github.com/google/go-cmp/cmp/cmpopts" /* copybara-comment */
	"google3/third_party/golang/github_com/go_jose/go_jose/v/v3/jose"
	"google3/third_party/golang/github_com/go_jose/go_jose/v/v3/jwt/jwt"
	"github.com/coreos/go-oidc" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/kms/localsign" /* copybara-comment: localsign */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/persona" /* copybara-comment: persona */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/httptestclient" /* copybara-comment: httptestclient */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */
)

func Test_SignJWT(t *testing.T) {
	iss := "http://iss.example.com"
	clientID := "client-1234"
	sub := "sub-1234"

	op, err := persona.NewBroker(iss, &testkeys.PersonaBrokerKey, "", "", false)
	if err != nil {
		t.Fatal("persona.NewBroker failed", err)
	}

	s := localsign.New(&testkeys.PersonaBrokerKey)

	claims := jwt.Claims{
		Issuer:   iss,
		Subject:  sub,
		Expiry:   jwt.NewNumericDate(time.Now().Add(10 * time.Hour)),
		Audience: []string{clientID},
	}

	header := map[string]string{
		"jku": "http://iss.example.com/.well-known/jwks",
	}

	ctx := context.Background()

	rawTok, err := s.SignJWT(ctx, claims, header)
	if err != nil {
		t.Fatal("SignJWT() failed", err)
	}

	withClient := oidc.ClientContext(ctx, httptestclient.New(op.Handler))
	p, err := oidc.NewProvider(withClient, iss)
	if err != nil {
		t.Fatalf("oidc.NewProvider() failed: %v", err)
	}

	idt, err := p.Verifier(&oidc.Config{ClientID: clientID}).Verify(withClient, rawTok)
	if err != nil {
		t.Fatalf("oidc.Verify() failed: %v", err)
	}

	if idt.Subject != sub {
		t.Errorf("sub = %s, wants %s", idt.Subject, sub)
	}

	tok, err := jwt.ParseSigned(rawTok)
	if err != nil {
		t.Fatalf("jwt.ParseSigned() failed: %v", err)
	}

	if len(tok.Headers) != 1 {
		t.Fatalf("len(t.Headers) %d, wants 1", len(tok.Headers))
	}

	wantHeader := jose.Header{
		KeyID:     string(testkeys.PersonaBroker),
		Algorithm: "RS256",
		ExtraHeaders: map[jose.HeaderKey]any{
			"jku": "http://iss.example.com/.well-known/jwks",
			"typ": "JWT",
		},
	}

	if d := cmp.Diff(wantHeader, tok.Headers[0], cmpopts.IgnoreUnexported(jose.Header{})); len(d) > 0 {
		t.Errorf("header (-want, +got): %s", d)
	}
}
