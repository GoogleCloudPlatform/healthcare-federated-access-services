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

package translator

import (
	"encoding/json"
	"io/ioutil"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"github.com/coreos/go-oidc" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/srcutil" /* copybara-comment: srcutil */
)

type testCase struct {
	name       string
	input      string
	translator TestTranslator
	cmpOptions []cmp.Option
	expected   string
}

type TestTranslator interface {
	TestTranslator(token *oidc.IDToken, payload []byte) (*ga4gh.Identity, error)
}

func testTranslator(t *testing.T, tests []testCase) {
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := ioutil.ReadFile(srcutil.Path(tc.input))
			if err != nil {
				t.Fatalf("failed to read input file %q: %v", tc.input, err)
			}
			token := &dbGapIdToken{}
			if err := json.Unmarshal(payload, token); err != nil {
				t.Fatalf("failed to unmarshal ID token: %v", err)
			}

			got, err := tc.translator.TestTranslator(convertToOIDCIDToken(*token), payload)
			if err != nil {
				t.Fatalf("failed during translation: %v", err)
			}

			str, err := ioutil.ReadFile(srcutil.Path(tc.expected))
			if err != nil {
				t.Fatalf("failed to read expected output file %q: %v", tc.expected, err)
			}
			want := &ga4gh.Identity{}
			if err := json.Unmarshal(str, want); err != nil {
				t.Fatalf("failed to unmarshal expected output %q: %v", tc.expected, err)
			}
			sort.Strings(got.VisaJWTs)

			opts := cmp.Options{cmp.Transformer("", ga4gh.MustVisaDataFromJWT)}
			if diff := cmp.Diff(want, got, opts); diff != "" {
				t.Errorf("returned diff (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_mergeIdentityWithUserinfo(t *testing.T) {
	id := &ga4gh.Identity{
		Subject: "s",
		Expiry:  1,
	}

	userinfo := &ga4gh.Identity{
		Expiry:   2,
		VisaJWTs: []string{"aaa"},
	}

	want := &ga4gh.Identity{
		Subject:  "s",
		Expiry:   1,
		VisaJWTs: []string{"aaa"},
	}

	mergeIdentityWithUserinfo(id, userinfo)

	if diff := cmp.Diff(want, id); len(diff) != 0 {
		t.Errorf("mergeIdentityWithUserinfo() (-want,+got): %s", diff)
	}
}
