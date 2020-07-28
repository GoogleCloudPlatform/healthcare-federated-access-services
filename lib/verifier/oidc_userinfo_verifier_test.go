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

package verifier

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/coreos/go-oidc" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/persona" /* copybara-comment: persona */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/httptestclient" /* copybara-comment: httptestclient */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */
)

func TestUserinfo_verify_ExtractClaims(t *testing.T) {
	issuer := "https://issuer.example.com"
	server, err := persona.NewBroker(issuer, &testkeys.PersonaBrokerKey, "dam-min", "testdata/config", false)
	if err != nil {
		t.Fatalf("persona.NewBroker() failed: %v", err)
	}

	client := httptestclient.New(server.Handler)
	ctx := oidc.ClientContext(context.Background(), client)

	v, err := NewAccessTokenVerifier(ctx, issuer, true)
	if err != nil {
		t.Fatalf("NewAccessTokenVerifier() failed: %v", err)
	}

	tok, _, err := persona.NewAccessToken("dr_joe_elixir", issuer, "", "", nil)
	if err != nil {
		t.Fatalf("NewAccessToken() failed: %v", err)
	}

	got := &ga4gh.Identity{}
	if err := v.Verify(ctx, string(tok), got, AccessTokenOption("", "", false)); err != nil {
		t.Errorf("Verify() failed: %v", err)
	}

	got.Expiry = 0
	got.VisaJWTs = nil

	want := &ga4gh.Identity{
		Subject:    "dr_joe_elixir",
		Issuer:     issuer,
		Scope:      "openid profile identities ga4gh_passport_v1 email",
		Username:   "dr_joe_elixir",
		Email:      "dr_joe@faculty.example.edu",
		Name:       "Dr Joe",
		Nickname:   "dr",
		GivenName:  "Dr",
		FamilyName: "Joe",
	}
	if d := cmp.Diff(want, got); len(d) > 0 {
		t.Errorf("ExtractClaims (-want, +got): %s", d)
	}
}

func TestUserinfo_verify_Error(t *testing.T) {
	issuer := "https://issuer.example.com"
	server, err := persona.NewBroker(issuer, &testkeys.PersonaBrokerKey, "dam-min", "testdata/config", false)
	if err != nil {
		t.Fatalf("persona.NewBroker() failed: %v", err)
	}

	client := httptestclient.New(server.Handler)
	ctx := oidc.ClientContext(context.Background(), client)

	v, err := NewAccessTokenVerifier(ctx, issuer, true)
	if err != nil {
		t.Fatalf("NewAccessTokenVerifier() failed: %v", err)
	}

	err = v.Verify(ctx, "invalid-token", nil, AccessTokenOption("", "", false))
	if err == nil {
		t.Errorf("Verify() should fail")
	}

	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("Verify() should fail with Unauthenticated, got %v", err)
	}
}