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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys"
)

func TestVisasToOldClaims(t *testing.T) {
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
					Value:  "faculty@issuer0.org",
					Source: Pattern("const:http://" + string(testkeys.VisaIssuer0) + ".org"),
				},
			},
			{
				{
					Type:   AffiliationAndRole,
					Value:  "faculty@issuer1.org",
					Source: Pattern("const:http://" + string(testkeys.VisaIssuer1) + ".org"),
				},
			},
		},
	}
	v1 := newVisa(t, iss0, ID{Issuer: string(testkeys.VisaIssuer0), Subject: "subject1"}, a1)
	v2 := newVisa(t, iss1, ID{Issuer: string(testkeys.VisaIssuer1), Subject: "subject2"}, a2)
	v3 := newVisa(t, iss0, ID{Issuer: string(testkeys.VisaIssuer1), Subject: "subject1"}, a3)
	vs := []VisaJWT{v1.JWT(), v2.JWT(), v3.JWT()}
	got := VisasToOldClaims(vs)
	want := map[string][]OldClaim{
		string(AffiliationAndRole): []OldClaim{
			{
				Value:    "faculty@issuer0.org",
				Source:   "http://testkeys-visa-issuer-0.org",
				By:       "so",
				Asserted: 10000,
			},
			{
				Value:    "faculty@issuer1.org",
				Source:   "http://testkeys-visa-issuer-1.org",
				Asserted: 10100,
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
						Value: []string{
							"faculty@issuer0.org",
							"faculty@issuer1.org",
						},
						Source: []string{
							"const:http://testkeys-visa-issuer-0.org",
							"const:http://testkeys-visa-issuer-1.org",
						},
					},
				},
			},
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("VisasToOldClaims(%+v) returned diff (-want +got):\n%s", vs, diff)
	}
}
