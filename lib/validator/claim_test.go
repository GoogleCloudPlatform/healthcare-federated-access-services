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

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
)

var (
	testnow          = time.Now().Unix()
	testnowf         = float64(testnow)
	bonaFideIdentity = &ga4gh.Identity{
		Issuer:  "https://issuer.org",
		Subject: "subject1",
		GA4GH: map[string][]ga4gh.OldClaim{
			"BonaFide": {
				{
					Value:       "https://bonafide.org/v1",
					Source:      "https://source.org",
					By:          "so",
					Asserted:    testnowf - 3600,
					Expires:     testnowf + 10*3600,
					VisaData:    &ga4gh.VisaData{StdClaims: ga4gh.StdClaims{IssuedAt: testnow - 600}},
					TokenFormat: ga4gh.DocumentVisaFormat,
				},
			},
		},
	}
	bonaFide2ndIdentity = &ga4gh.Identity{
		Issuer:  "https://issuer.org",
		Subject: "subject1",
		GA4GH: map[string][]ga4gh.OldClaim{
			"BonaFide": {
				{
					Value:       "https://bonafide.org/v1",
					Source:      "https://badsource.com",
					By:          "so",
					Asserted:    testnowf - 3600,
					Expires:     testnowf + 3600,
					VisaData:    &ga4gh.VisaData{StdClaims: ga4gh.StdClaims{IssuedAt: testnow - 600}},
					TokenFormat: ga4gh.DocumentVisaFormat,
				},
				{
					Value:       "https://bonafide.org/v1",
					Source:      "https://source.org",
					By:          "so",
					Asserted:    float64(time.Now().Unix()) - 3600,
					Expires:     float64(time.Now().Unix()) + 3600,
					VisaData:    &ga4gh.VisaData{StdClaims: ga4gh.StdClaims{IssuedAt: testnow - 600}},
					TokenFormat: ga4gh.DocumentVisaFormat,
				},
			},
		},
	}
	metConditionIdentity = &ga4gh.Identity{
		Issuer:  "https://issuer.org",
		Subject: "subject1",
		GA4GH: map[string][]ga4gh.OldClaim{
			"AffiliationAndRole": {
				{
					Value:       "faculty@myuni.edu",
					Source:      "https://source.org",
					By:          "so",
					Asserted:    testnowf - 3600,
					Expires:     testnowf + 3600,
					VisaData:    &ga4gh.VisaData{StdClaims: ga4gh.StdClaims{IssuedAt: testnow - 600}},
					TokenFormat: ga4gh.DocumentVisaFormat,
				},
			},
			"ControlledAccessGrants": {
				{
					Value:    "https://datasets.org/123",
					Source:   "https://source.org",
					By:       "dac",
					Asserted: testnowf - 3600,
					Expires:  testnowf + 10*3600,
					Condition: map[string]ga4gh.OldClaimCondition{
						"AffiliationAndRole": {
							Value: []string{"student@myuni.edu", "faculty@myuni.edu"},
							By:    []string{"system", "so"},
						},
					},
					VisaData:    &ga4gh.VisaData{StdClaims: ga4gh.StdClaims{IssuedAt: testnow - 600}},
					TokenFormat: ga4gh.DocumentVisaFormat,
				},
			},
		},
	}
	unmetConditionIdentity = &ga4gh.Identity{
		Issuer:  "https://issuer.org",
		Subject: "subject1",
		GA4GH: map[string][]ga4gh.OldClaim{
			"AffiliationAndRole": {
				{
					Value:       "student@myuni.edu",
					Source:      "https://source.org",
					By:          "so",
					Asserted:    testnowf - 3600,
					Expires:     testnowf + 10*3600,
					VisaData:    &ga4gh.VisaData{StdClaims: ga4gh.StdClaims{IssuedAt: testnow - 600}},
					TokenFormat: ga4gh.DocumentVisaFormat,
				},
			},
			"ControlledAccessGrants": {
				{
					Value:    "https://datasets.org/123",
					Source:   "https://source.org",
					By:       "dac",
					Asserted: testnowf - 3600,
					Expires:  testnowf + 10*3600,
					Condition: map[string]ga4gh.OldClaimCondition{
						"AffiliationAndRole": {
							Value: []string{"faculty@myuni.edu"},
							By:    []string{"system", "so"},
						},
					},
					VisaData:    &ga4gh.VisaData{StdClaims: ga4gh.StdClaims{IssuedAt: testnow - 600}},
					TokenFormat: ga4gh.DocumentVisaFormat,
				},
			},
		},
	}
	accessTokenVisaIdentity = &ga4gh.Identity{
		Issuer:  "https://issuer.org",
		Subject: "subject1",
		GA4GH: map[string][]ga4gh.OldClaim{
			"BonaFide": {
				{
					Value:       "https://bonafide.org/v1",
					Source:      "https://source.org",
					By:          "so",
					Asserted:    testnowf - 3*3600,
					Expires:     testnowf + 10*3600,
					VisaData:    &ga4gh.VisaData{StdClaims: ga4gh.StdClaims{IssuedAt: testnow - 600}},
					TokenFormat: ga4gh.AccessTokenVisaFormat,
				},
			},
		},
	}
)

func TestClaimValidator(t *testing.T) {
	tests := []struct {
		name     string
		id       *ga4gh.Identity
		claim    string
		values   []string
		isNot    bool
		sources  []string
		by       []string
		ttl      float64
		approved bool
	}{
		{
			name:     "empty identity",
			id:       &ga4gh.Identity{},
			claim:    "BonaFide",
			values:   []string{"https://bonafide.org/v1"},
			approved: false,
		},
		{
			name:     "bona fide value",
			id:       bonaFideIdentity,
			claim:    "BonaFide",
			values:   []string{"https://bonafide.org/v1"},
			ttl:      3600,
			approved: true,
		},
		{
			name:     "bona fide values",
			id:       bonaFideIdentity,
			claim:    "BonaFide",
			values:   []string{"aaaa", "https://bonafide.org/v1"},
			approved: true,
		},
		{
			name:     "bona fide sources",
			id:       bonaFideIdentity,
			claim:    "BonaFide",
			values:   []string{"https://bonafide.org/v1"},
			sources:  []string{"https://source.org"},
			approved: true,
		},
		{
			name:     "bona fide sources and by",
			id:       bonaFideIdentity,
			claim:    "BonaFide",
			values:   []string{"https://bonafide.org/v1"},
			sources:  []string{"https://source.org"},
			by:       []string{"so"},
			approved: true,
		},
		{
			name:     "bona fide mismatch sources",
			id:       bonaFideIdentity,
			claim:    "BonaFide",
			values:   []string{"https://bonafide.org/v1"},
			sources:  []string{"https://wrong_answer.org"},
			by:       []string{"so"},
			approved: false,
		},
		{
			name:     "bona fide mismatch by",
			id:       bonaFideIdentity,
			claim:    "BonaFide",
			values:   []string{"https://bonafide.org/v1"},
			sources:  []string{"https://source.org"},
			by:       []string{"self"},
			approved: false,
		},
		{
			name:     "bona fide match 2nd entry",
			id:       bonaFide2ndIdentity,
			claim:    "BonaFide",
			values:   []string{"https://bonafide.org/v1"},
			sources:  []string{"https://source.org"},
			by:       []string{"so"},
			approved: true,
		},
		{
			name:     "bona fide match nothing on a list",
			id:       bonaFide2ndIdentity,
			claim:    "BonaFide",
			values:   []string{"https://bonafide.org/v1"},
			sources:  []string{"https://source_no_match.org"},
			by:       []string{"so"},
			approved: false,
		},
		{
			name:     "duration validate because now + ttl < expires",
			id:       bonaFideIdentity,
			claim:    "BonaFide",
			values:   []string{"https://bonafide.org/v1"},
			sources:  []string{"https://source.org"},
			by:       []string{"so"},
			ttl:      10*3600 - 300,
			approved: true,
		},
		{
			name:     "duration invalidate because now + ttl > expires",
			id:       bonaFideIdentity,
			claim:    "BonaFide",
			values:   []string{"https://bonafide.org/v1"},
			sources:  []string{"https://source.org"},
			by:       []string{"so"},
			ttl:      10*3600 + 5,
			approved: false,
		},
		{
			name:     "condition met",
			id:       metConditionIdentity,
			claim:    "ControlledAccessGrants",
			values:   []string{"https://datasets.org/123"},
			sources:  []string{"https://source.org"},
			by:       []string{"dac"},
			approved: true,
		},
		{
			name:     "condition met but expired",
			id:       metConditionIdentity,
			claim:    "ControlledAccessGrants",
			values:   []string{"https://datasets.org/123"},
			sources:  []string{"https://source.org"},
			by:       []string{"dac"},
			ttl:      3605,
			approved: false,
		},
		{
			name:     "condition unmet",
			id:       unmetConditionIdentity,
			claim:    "ControlledAccessGrants",
			values:   []string{"https://datasets.org/123"},
			sources:  []string{"https://source.org"},
			by:       []string{"dac"},
			approved: false,
		},
		{
			name:     "access token visa short lived",
			id:       accessTokenVisaIdentity,
			claim:    "BonaFide",
			values:   []string{"https://bonafide.org/v1"},
			ttl:      600,
			approved: true,
		},
		{
			name:     "access token visa longer lived",
			id:       accessTokenVisaIdentity,
			claim:    "BonaFide",
			values:   []string{"https://bonafide.org/v1"},
			ttl:      3600,
			approved: false,
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
			ctx := context.WithValue(context.Background(), RequestTTLInNanoFloat64, test.ttl)
			approved, err := v.Validate(ctx, test.id)
			if err != nil {
				t.Fatalf("test case %q Validate(ctx, %+v) failed: %v", test.name, test.id, err)
			}
			if test.approved != approved {
				t.Fatalf("Unexpected validation result of %q: got = %v, wanted = %v", test.name, approved, test.approved)
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
