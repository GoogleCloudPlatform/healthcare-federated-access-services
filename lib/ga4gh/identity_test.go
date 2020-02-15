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
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/globalflags" /* copybara-comment: globalflags */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */
)

func testVisaSetup(t *testing.T) []VisaJWT {
	t.Helper()

	iss0 := testkeys.Keys[testkeys.VisaIssuer0]
	iss1 := testkeys.Keys[testkeys.VisaIssuer1]
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
	v1 := newVisa(t, iss0, ID{Issuer: string(testkeys.VisaIssuer0), Subject: "subject1"}, a1)
	v2 := newVisa(t, iss1, ID{Issuer: string(testkeys.VisaIssuer1), Subject: "subject2"}, a2)
	v3 := newVisa(t, iss0, ID{Issuer: string(testkeys.VisaIssuer1), Subject: "subject1"}, a3)

	return []VisaJWT{v1.JWT(), v2.JWT(), v3.JWT()}
}

func TestVisasToOldClaims(t *testing.T) {
	globalflags.Experimental = true
	defer func() { globalflags.Experimental = false }()

	visas := testVisaSetup(t)
	ctx := context.Background()
	validator := func(context.Context, string) error {
		return nil
	}
	got, skipped, err := VisasToOldClaims(ctx, visas, validator)
	if err != nil {
		t.Fatalf("VisasToOldClaims(vs) returned error: %v", err)
	}
	if skipped != 0 {
		t.Fatalf("VisasToOldClaims(vs) = (%v, %d, %v), wanted not to skip over visas", got, skipped, err)
	}
	want := map[string][]OldClaim{
		string(AffiliationAndRole): []OldClaim{
			{
				Value:    "faculty@issuer0.org",
				Source:   "http://testkeys-visa-issuer-0.org",
				By:       "so",
				Asserted: 10000,
				Issuer:   string(testkeys.VisaIssuer0),
			},
			{
				Value:    "faculty@issuer1.org",
				Source:   "http://testkeys-visa-issuer-1.org",
				Asserted: 10100,
				Issuer:   string(testkeys.VisaIssuer1),
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
				Issuer: string(testkeys.VisaIssuer1),
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
	invalidator := func(context.Context, string) error {
		return fmt.Errorf("invalid token visa")
	}
	if got, skipped, err := VisasToOldClaims(ctx, visas, invalidator); skipped != len(visas) || err != nil {
		t.Errorf("experimental settings with invalid visas: VisasToOldClaims(ctx, vs, invalidator) = (%+v, %d, %v), want to skip %d visas without error", got, skipped, err, len(visas))
	}
}

func TestVisasToOldClaims_NonExperimental(t *testing.T) {
	// Non-experimental mode should skip visas with conditions.
	visas := testVisaSetup(t)
	ctx := context.Background()
	validator := func(context.Context, string) error {
		return nil
	}
	visasWithConditions := 1
	if got, skipped, err := VisasToOldClaims(ctx, visas, validator); skipped != visasWithConditions || err != nil {
		t.Errorf("production settings: VisasToOldClaims(ctx, vs, invalidator) = (%+v, %d, %v), want to skip %d visas without error", got, skipped, err, visasWithConditions)
	}
}

func TestVisasToOldClaims_Errors(t *testing.T) {
	globalflags.Experimental = true
	defer func() { globalflags.Experimental = false }()

	tests := []struct {
		name       string
		conditions [][]Condition
		err        string
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
			err: "multiple conditions on the same visa type",
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
			err: "OR conditions are not supported",
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
			err: "non-const condition",
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
			err: "non-const condition",
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
			err: "non-const condition",
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
	v1 := newVisa(t, iss0, ID{Issuer: string(testkeys.VisaIssuer0), Subject: "subject1"}, a1)
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
		v2 := newVisa(t, iss1, ID{Issuer: string(testkeys.VisaIssuer1), Subject: "subject2"}, a2)
		vs := []VisaJWT{v1.JWT(), v2.JWT()}
		got, skipped, err := VisasToOldClaims(ctx, vs, tc.verifier)
		if err == nil {
			t.Fatalf("test case %q: VisasToOldClaims(vs) = (%v, %d, %v) returned unexpected success", tc.name, got, skipped, err)
		}
		if !strings.Contains(err.Error(), tc.err) {
			t.Errorf("test case %q: VisasToOldClaims(vs) = (%v, %d, %v), error want fragment %q", tc.name, got, skipped, err, tc.err)
		}
		if skipped != 0 {
			t.Errorf("test case %q: VisasToOldClaims(vs) = (%v, %d, %v), unexpectedly skipped some visas", tc.name, got, skipped, err)
		}
	}
}
