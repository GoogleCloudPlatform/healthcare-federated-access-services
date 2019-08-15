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

package validator

import (
	"context"
	"testing"
	"time"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh"
)

var (
	bonaFideIdentity = &ga4gh.Identity{
		Issuer:  "https://issuer.org",
		Subject: "subject1",
		GA4GH: map[string][]ga4gh.Claim{
			"BonaFide": {
				{
					Value:    "https://bonafide.org/v1",
					Source:   "https://source.org",
					By:       "so",
					Asserted: float64(time.Now().Unix()) - 3600,
					Expires:  float64(time.Now().Unix()) + 3600,
				},
			},
		},
	}
	bonaFide2ndIdentity = &ga4gh.Identity{
		Issuer:  "https://issuer.org",
		Subject: "subject1",
		GA4GH: map[string][]ga4gh.Claim{
			"BonaFide": {
				{
					Value:    "https://bonafide.org/v1",
					Source:   "https://badsource.com",
					By:       "so",
					Asserted: float64(time.Now().Unix()) - 3600,
					Expires:  float64(time.Now().Unix()) + 3600,
				},
				{
					Value:    "https://bonafide.org/v1",
					Source:   "https://source.org",
					By:       "so",
					Asserted: float64(time.Now().Unix()) - 3600,
					Expires:  float64(time.Now().Unix()) + 3600,
				},
			},
		},
	}
	metConditionIdentity = &ga4gh.Identity{
		Issuer:  "https://issuer.org",
		Subject: "subject1",
		GA4GH: map[string][]ga4gh.Claim{
			"AffiliationAndRole": {
				{
					Value:    "faculty@myuni.edu",
					Source:   "https://source.org",
					By:       "so",
					Asserted: float64(time.Now().Unix()) - 3600,
					Expires:  float64(time.Now().Unix()) + 3600,
				},
			},
			"ControlledAccessGrants": {
				{
					Value:    "https://datasets.org/123",
					Source:   "https://source.org",
					By:       "dac",
					Asserted: float64(time.Now().Unix()) - 3600,
					Expires:  float64(time.Now().Unix()) + 10*3600,
					Condition: map[string]ga4gh.ClaimCondition{
						"AffiliationAndRole": {
							Value: []string{"student@myuni.edu", "faculty@myuni.edu"},
							By:    []string{"system", "so"},
						},
					},
				},
			},
		},
	}
	unmetConditionIdentity = &ga4gh.Identity{
		Issuer:  "https://issuer.org",
		Subject: "subject1",
		GA4GH: map[string][]ga4gh.Claim{
			"AffiliationAndRole": {
				{
					Value:    "student@myuni.edu",
					Source:   "https://source.org",
					By:       "so",
					Asserted: float64(time.Now().Unix()) - 3600,
					Expires:  float64(time.Now().Unix()) + 10*3600,
				},
			},
			"ControlledAccessGrants": {
				{
					Value:    "https://datasets.org/123",
					Source:   "https://source.org",
					By:       "dac",
					Asserted: float64(time.Now().Unix()) - 3600,
					Expires:  float64(time.Now().Unix()) + 10*3600,
					Condition: map[string]ga4gh.ClaimCondition{
						"AffiliationAndRole": {
							Value: []string{"faculty@myuni.edu"},
							By:    []string{"system", "so"},
						},
					},
				},
			},
		},
	}
)

func TestClaimValidator(t *testing.T) {
	tests := []struct {
		name    string
		id      *ga4gh.Identity
		claim   string
		values  []string
		isNot   bool
		sources []string
		by      []string
		ttl     float64
		ok      bool
		err     bool
	}{
		{
			name:   "empty identity",
			id:     &ga4gh.Identity{},
			claim:  "BonaFide",
			values: []string{"https://bonafide.org/v1"},
			ok:     false,
		},
		{
			name:   "bona fide value",
			id:     bonaFideIdentity,
			claim:  "BonaFide",
			values: []string{"https://bonafide.org/v1"},
			ok:     true,
		},
		{
			name:   "bona fide values",
			id:     bonaFideIdentity,
			claim:  "BonaFide",
			values: []string{"aaaa", "https://bonafide.org/v1"},
			ok:     true,
		},
		{
			name:    "bona fide sources",
			id:      bonaFideIdentity,
			claim:   "BonaFide",
			values:  []string{"https://bonafide.org/v1"},
			sources: []string{"https://source.org"},
			ok:      true,
		},
		{
			name:    "bona fide sources and by",
			id:      bonaFideIdentity,
			claim:   "BonaFide",
			values:  []string{"https://bonafide.org/v1"},
			sources: []string{"https://source.org"},
			by:      []string{"so"},
			ok:      true,
		},
		{
			name:    "bona fide mismatch sources",
			id:      bonaFideIdentity,
			claim:   "BonaFide",
			values:  []string{"https://bonafide.org/v1"},
			sources: []string{"https://wrong_answer.org"},
			by:      []string{"so"},
			ok:      false,
		},
		{
			name:    "bona fide mismatch by",
			id:      bonaFideIdentity,
			claim:   "BonaFide",
			values:  []string{"https://bonafide.org/v1"},
			sources: []string{"https://source.org"},
			by:      []string{"self"},
			ok:      false,
		},
		{
			name:    "bona fide match 2nd entry",
			id:      bonaFide2ndIdentity,
			claim:   "BonaFide",
			values:  []string{"https://bonafide.org/v1"},
			sources: []string{"https://source.org"},
			by:      []string{"so"},
			ok:      true,
		},
		{
			name:    "bona fide match nothing on a list",
			id:      bonaFide2ndIdentity,
			claim:   "BonaFide",
			values:  []string{"https://bonafide.org/v1"},
			sources: []string{"https://source_no_match.org"},
			by:      []string{"so"},
			ok:      false,
		},
		{
			name:    "duration validate because now + ttl < expires",
			id:      bonaFideIdentity,
			claim:   "BonaFide",
			values:  []string{"https://bonafide.org/v1"},
			sources: []string{"https://source.org"},
			by:      []string{"so"},
			ttl:     3595,
			ok:      true,
		},
		{
			name:    "duration invalidate because now + ttl > expires",
			id:      bonaFideIdentity,
			claim:   "BonaFide",
			values:  []string{"https://bonafide.org/v1"},
			sources: []string{"https://source.org"},
			by:      []string{"so"},
			ttl:     3605,
			ok:      false,
		},
		{
			name:    "condition met",
			id:      metConditionIdentity,
			claim:   "ControlledAccessGrants",
			values:  []string{"https://datasets.org/123"},
			sources: []string{"https://source.org"},
			by:      []string{"dac"},
			ok:      true,
		},
		{
			name:    "condition met but expired",
			id:      metConditionIdentity,
			claim:   "ControlledAccessGrants",
			values:  []string{"https://datasets.org/123"},
			sources: []string{"https://source.org"},
			by:      []string{"dac"},
			ttl:     3605,
			ok:      false,
		},
		{
			name:    "condition unmet",
			id:      unmetConditionIdentity,
			claim:   "ControlledAccessGrants",
			values:  []string{"https://datasets.org/123"},
			sources: []string{"https://source.org"},
			by:      []string{"dac"},
			ok:      false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			is := ""
			if test.isNot {
				is = "!="
			}
			v, err := NewClaimValidator(test.claim, test.values, is, strMap(test.sources), strMap(test.by))
			if err != nil {
				t.Fatalf("Unexpected error during validator creation of %q: %v", test.name, err)
			}
			ctx := context.WithValue(context.Background(), requestTTLInNanoFloat64, test.ttl)
			ok, err := v.Validate(ctx, test.id)
			if test.err != (err != nil) {
				t.Fatalf("Unexpected error during validation of %q: %v", test.name, err)
			}
			if test.ok != ok {
				t.Fatalf("Unexpected validation result of %q: got = %v, wanted = %v", test.name, ok, test.ok)
			}
		})
	}
}

func strMap(strs []string) map[string]bool {
	out := make(map[string]bool)
	for _, str := range strs {
		out[str] = true
	}
	return out
}
