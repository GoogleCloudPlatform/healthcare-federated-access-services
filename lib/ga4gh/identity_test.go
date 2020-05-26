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

package ga4gh

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/globalflags" /* copybara-comment: globalflags */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */
)

var (
	issuer = "https://example.com/"
	jku    = "https://example.com/jwks"
)

func testVisaSetup(t *testing.T) []VisaJWT {
	t.Helper()

	iss0 := testkeys.Keys[testkeys.VisaIssuer0]
	a1 := Assertion{
		Type:     AffiliationAndRole,
		Value:    "faculty@issuer0.org",
		Source:   Source("http://" + string(testkeys.VisaIssuer0) + ".org"),
		Asserted: 10000,
		By:       "so",
	}
	a2 := Assertion{
		Type:     AffiliationAndRole,
		Value:    "faculty@issuer1.org",
		Source:   Source("http://" + string(testkeys.VisaIssuer1) + ".org"),
		Asserted: 10100,
	}
	a3 := Assertion{
		Type:     ControlledAccessGrants,
		Value:    "https://dataset.example.org/123",
		Source:   Source("http://" + string(testkeys.VisaIssuer1) + ".org"),
		Asserted: 10200,
		By:       "dac",
		Conditions: [][]Condition{
			{
				{
					Type:   AffiliationAndRole,
					Value:  "const:faculty@issuer0.org",
					Source: Pattern("const:http://" + string(testkeys.VisaIssuer0) + ".org"),
					By:     Pattern("const:so"),
				},
				{
					Type:  AcceptedTermsAndPolicies,
					Value: "const:https://agreements.example.org/agreement123",
				},
			},
		},
	}
	a4 := Assertion{
		Type:     LinkedIdentities,
		Value:    "user1%40example1.org,https%3A%2F%2Foidc.example1.org;user2%40example2.org,https%3A%2F%2Foidc.example2.org",
		Source:   Source("http://" + string(testkeys.VisaIssuer1) + ".org"),
		Asserted: 10200,
		By:       "system",
	}
	a5 := Assertion{
		Type:     AcceptedTermsAndPolicies,
		Value:    "https://agreements.example.org/ds123",
		Source:   Source("http://" + string(testkeys.VisaIssuer0) + ".org"),
		Asserted: 10100,
	}
	v1 := newVisa(t, iss0, ID{Issuer: issuer, Subject: "subject1"}, a1, "", jku)
	v2 := newVisa(t, iss0, ID{Issuer: issuer, Subject: "subject2"}, a2, "", jku)
	v3 := newVisa(t, iss0, ID{Issuer: issuer, Subject: "subject1"}, a3, "", jku)
	v4 := newVisa(t, iss0, ID{Issuer: issuer, Subject: "subject1"}, a4, "", jku)
	v5 := newVisa(t, iss0, ID{Issuer: issuer, Subject: "subject1"}, a5, "openid", "")

	return []VisaJWT{v1.JWT(), v2.JWT(), v3.JWT(), v4.JWT(), v5.JWT()}
}

func TestVisasToOldClaims(t *testing.T) {
	globalflags.Experimental = true
	defer func() { globalflags.Experimental = false }()

	visas := testVisaSetup(t)
	ctx := context.Background()
	validator := func(context.Context, string, string, string) error {
		return nil
	}
	got, rejected, err := VisasToOldClaims(ctx, visas, validator)
	if err != nil {
		t.Fatalf("VisasToOldClaims(vs) returned error: %v", err)
	}
	if len(rejected) != 0 {
		t.Fatalf("VisasToOldClaims(vs) = (%v, %+v, %v), wanted not to skip over visas", got, rejected, err)
	}
	want := map[string][]OldClaim{
		string(AffiliationAndRole): []OldClaim{
			{
				Value:    "faculty@issuer0.org",
				Source:   "http://testkeys-visa-issuer-0.org",
				By:       "so",
				Asserted: 10000,
				Issuer:   issuer,
				VisaData: &VisaData{
					StdClaims: StdClaims{Issuer: issuer, Subject: "subject1"},
					Assertion: Assertion{
						Type:     "AffiliationAndRole",
						Value:    "faculty@issuer0.org",
						Source:   "http://testkeys-visa-issuer-0.org",
						By:       "so",
						Asserted: 10000,
					},
				},
				TokenFormat: DocumentVisaFormat,
			},
			{
				Value:    "faculty@issuer1.org",
				Source:   "http://testkeys-visa-issuer-1.org",
				Asserted: 10100,
				Issuer:   issuer,
				VisaData: &VisaData{
					StdClaims: StdClaims{Issuer: issuer, Subject: "subject2"},
					Assertion: Assertion{
						Type:     "AffiliationAndRole",
						Value:    "faculty@issuer1.org",
						Source:   "http://testkeys-visa-issuer-1.org",
						Asserted: 10100,
					},
				},
				TokenFormat: DocumentVisaFormat,
			},
		},
		string(ControlledAccessGrants): []OldClaim{
			{
				Value:    "https://dataset.example.org/123",
				Source:   "http://testkeys-visa-issuer-1.org",
				By:       "dac",
				Asserted: 10200,
				Condition: map[string]OldClaimCondition{
					string(AffiliationAndRole): {
						Value:  []string{"faculty@issuer0.org"},
						Source: []string{"http://testkeys-visa-issuer-0.org"},
						By:     []string{"so"},
					},
					string(AcceptedTermsAndPolicies): {
						Value: []string{"https://agreements.example.org/agreement123"},
					},
				},
				Issuer: issuer,
				VisaData: &VisaData{
					StdClaims: StdClaims{Issuer: issuer, Subject: "subject1"},
					Assertion: Assertion{
						Type:     "ControlledAccessGrants",
						Value:    "https://dataset.example.org/123",
						Source:   "http://testkeys-visa-issuer-1.org",
						By:       "dac",
						Asserted: 10200,
						Conditions: Conditions{
							{
								{
									Type:   "AffiliationAndRole",
									Value:  "const:faculty@issuer0.org",
									Source: "const:http://testkeys-visa-issuer-0.org",
									By:     "const:so",
								},
								{
									Type:  "AcceptedTermsAndPolicies",
									Value: "const:https://agreements.example.org/agreement123",
								},
							},
						},
					},
				},
				TokenFormat: DocumentVisaFormat,
			},
		},
		string(LinkedIdentities): []OldClaim{
			{
				Value:    "user1%40example1.org,https%3A%2F%2Foidc.example1.org",
				Source:   "http://testkeys-visa-issuer-1.org",
				By:       "system",
				Asserted: 10200,
				Issuer:   issuer,
				VisaData: &VisaData{
					StdClaims: StdClaims{Issuer: issuer, Subject: "subject1"},
					Assertion: Assertion{
						Type:     "LinkedIdentities",
						Value:    "user1%40example1.org,https%3A%2F%2Foidc.example1.org;user2%40example2.org,https%3A%2F%2Foidc.example2.org",
						Source:   "http://testkeys-visa-issuer-1.org",
						By:       "system",
						Asserted: 10200,
					},
				},
				TokenFormat: DocumentVisaFormat,
			},
			{
				Value:    "user2%40example2.org,https%3A%2F%2Foidc.example2.org",
				Source:   "http://testkeys-visa-issuer-1.org",
				By:       "system",
				Asserted: 10200,
				Issuer:   issuer,
				VisaData: &VisaData{
					StdClaims: StdClaims{Issuer: issuer, Subject: "subject1"},
					Assertion: Assertion{
						Type:     "LinkedIdentities",
						Value:    "user1%40example1.org,https%3A%2F%2Foidc.example1.org;user2%40example2.org,https%3A%2F%2Foidc.example2.org",
						Source:   "http://testkeys-visa-issuer-1.org",
						By:       "system",
						Asserted: 10200,
					},
				},
				TokenFormat: DocumentVisaFormat,
			},
		},
		string(AcceptedTermsAndPolicies): []OldClaim{
			{
				Value:    "https://agreements.example.org/ds123",
				Source:   "http://testkeys-visa-issuer-0.org",
				Asserted: 10100,
				Issuer:   "https://example.com/",
				VisaData: &VisaData{
					StdClaims: StdClaims{Issuer: "https://example.com/", Subject: "subject1"},
					Scope:     "openid",
					Assertion: Assertion{
						Type:     "AcceptedTermsAndPolicies",
						Value:    "https://agreements.example.org/ds123",
						Source:   "http://testkeys-visa-issuer-0.org",
						Asserted: 10100,
					},
				},
				TokenFormat: "access_token",
			},
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("VisasToOldClaims(ctx, %+v, nil) returned diff (-want +got):\n%s", visas, diff)
	}
}

func TestVisasToOldClaims_Invalid(t *testing.T) {
	globalflags.Experimental = true
	defer func() { globalflags.Experimental = false }()

	visas := testVisaSetup(t)
	ctx := context.Background()
	invalidator := func(context.Context, string, string, string) error {
		return fmt.Errorf("invalid token visa")
	}
	if got, rejected, err := VisasToOldClaims(ctx, visas, invalidator); len(rejected) != len(visas) || err != nil {
		t.Errorf("experimental settings with invalid visas: VisasToOldClaims(ctx, vs, invalidator) = (%+v, %+v, %v), want to skip %d visas without error", got, rejected, err, len(visas))
	}
}

func TestVisasToOldClaims_NonExperimental(t *testing.T) {
	// Non-experimental mode should skip visas with conditions.
	visas := testVisaSetup(t)
	ctx := context.Background()
	validator := func(context.Context, string, string, string) error {
		return nil
	}
	visasWithConditions := 1
	if got, rejected, err := VisasToOldClaims(ctx, visas, validator); len(rejected) != visasWithConditions || err != nil {
		t.Errorf("production settings: VisasToOldClaims(ctx, vs, invalidator) = (%+v, %+v, %v), want to skip %d visas without error", got, rejected, err, visasWithConditions)
	}
}

func TestVisasToOldClaims_Rejections(t *testing.T) {
	globalflags.Experimental = true
	defer func() { globalflags.Experimental = false }()

	tests := []struct {
		name       string
		conditions [][]Condition
		reason     string // rejection reason
		verifier   JWTVerifier
	}{
		{
			name: "multiple conditions with the same visa type",
			conditions: [][]Condition{
				{
					{
						Type:   AffiliationAndRole,
						Value:  "const:faculty@issuer0.org",
						Source: Pattern("const:http://" + string(testkeys.VisaIssuer0) + ".org"),
						By:     Pattern("const:so"),
					},
					{
						Type:   AffiliationAndRole,
						Value:  "const:faculty@issuer1.org",
						Source: Pattern("const:http://" + string(testkeys.VisaIssuer1) + ".org"),
						By:     Pattern("const:so"),
					},
				},
			},
			reason: "condition_not_supported",
		},
		{
			name: "OR conditions",
			conditions: [][]Condition{
				{
					{
						Type:   AffiliationAndRole,
						Value:  "const:faculty@issuer0.org",
						Source: Pattern("const:http://" + string(testkeys.VisaIssuer0) + ".org"),
						By:     Pattern("const:so"),
					},
				},
				{
					{
						Type:  AcceptedTermsAndPolicies,
						Value: "const:https://agreements.example.org/agreement123",
					},
				},
			},
			reason: "condition_not_supported",
		},
		{
			name: "non-const value condition",
			conditions: [][]Condition{
				{
					{
						Type:  AffiliationAndRole,
						Value: "pattern:faculty@issuer0.*",
					},
				},
			},
			reason: "condition_not_supported",
		},
		{
			name: "non-const source condition",
			conditions: [][]Condition{
				{
					{
						Type:   AffiliationAndRole,
						Source: "pattern:foo*",
					},
				},
			},
			reason: "condition_not_supported",
		},
		{
			name: "non-const by condition",
			conditions: [][]Condition{
				{
					{
						Type: AffiliationAndRole,
						By:   "pattern:foo*",
					},
				},
			},
			reason: "condition_not_supported",
		},
	}

	iss0 := testkeys.Keys[testkeys.VisaIssuer0]
	iss1 := testkeys.Keys[testkeys.VisaIssuer1]
	a1 := Assertion{
		Type:     AffiliationAndRole,
		Value:    "faculty@issuer0.org",
		Source:   Source("http://" + string(testkeys.VisaIssuer0) + ".org"),
		Asserted: 10000,
		By:       "so",
	}
	v1 := newVisa(t, iss0, ID{Issuer: issuer, Subject: "subject1"}, a1, "openid", "")
	ctx := context.Background()

	for _, tc := range tests {
		a2 := Assertion{
			Type:       ControlledAccessGrants,
			Value:      "https://dataset.example.org/123",
			Source:     Source("http://" + string(testkeys.VisaIssuer1) + ".org"),
			Asserted:   10200,
			By:         "dac",
			Conditions: tc.conditions,
		}
		v2 := newVisa(t, iss1, ID{Issuer: issuer, Subject: "subject2"}, a2, "openid", "")
		vs := []VisaJWT{v1.JWT(), v2.JWT()}
		got, rejected, err := VisasToOldClaims(ctx, vs, tc.verifier)
		if err != nil {
			t.Fatalf("test case %q: VisasToOldClaims(vs) = (%v, %+v, %v) failed", tc.name, got, rejected, err)
		}
		if len(rejected) == 0 {
			t.Fatalf("test case %q: VisasToOldClaims(vs) = (%v, %+v, %v) wanted at least one visa rejected", tc.name, got, rejected, err)
		}
		found := false
		for _, reject := range rejected {
			if reject.Rejection.Reason == tc.reason {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("test case %q: VisasToOldClaims(vs) = (%v, %+v, %v), wanted reason %q not found", tc.name, got, rejected, err, tc.reason)
		}
	}
}

func TestVisasToOldClaims_Error(t *testing.T) {
	tests := []struct {
		name   string
		scope  string
		issuer string
		jku    string
		reason string
	}{
		{
			name:   "no openid no jku",
			scope:  "",
			issuer: issuer,
			jku:    "",
			reason: "no_openid_no_jku",
		},
		{
			name:   "openid and jku",
			scope:  "openid",
			issuer: issuer,
			jku:    jku,
			reason: "openid_jku",
		},
		{
			name:   "jku not same host",
			scope:  "",
			issuer: issuer,
			jku:    "https://other.com/jwks",
			reason: "jku_issuer_host",
		},
		{
			name:   "jku not https",
			scope:  "",
			issuer: issuer,
			jku:    "http://example.com/jwks",
			reason: "jku_https",
		},
	}

	a := Assertion{
		Type:     ControlledAccessGrants,
		Value:    "https://dataset.example.org/123",
		Source:   Source(issuer),
		Asserted: 10200,
		By:       "dac",
	}

	iss0 := testkeys.Keys[testkeys.VisaIssuer0]
	ctx := context.Background()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := newVisa(t, iss0, ID{Issuer: tc.issuer, Subject: "sub"}, a, tc.scope, tc.jku)
			vs := []VisaJWT{v.JWT()}
			got, rejected, err := VisasToOldClaims(ctx, vs, func(i context.Context, jwt, iss, jku string) error {
				return nil
			})
			if err != nil {
				t.Fatalf("VisasToOldClaims(vs) = (%v, %+v, %v) failed", got, rejected, err)
			}
			if len(rejected) != 1 {
				t.Fatalf("VisasToOldClaims(vs) = (%v, %+v, %v) wanted one visa rejected", got, rejected, err)
			}

			if rejected[0].Rejection.Reason != tc.reason {
				t.Errorf("Rejection.Reason = %s, wants %s", rejected[0].Rejection.Reason, tc.reason)
			}
		})
	}
}
