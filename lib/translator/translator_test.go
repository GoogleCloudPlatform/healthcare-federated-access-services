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
	"path/filepath"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/coreos/go-oidc"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage"
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

func sortClaims() cmp.Option {
	// This comparison option sorts the claims to avoid different orders in the output.
	return cmp.Transformer("SortClaims", func(in []ga4gh.OldClaim) []ga4gh.OldClaim {
		out := append([]ga4gh.OldClaim{}, in...)
		sort.Slice(out, func(i, j int) bool { return out[i].Value < out[j].Value })
		return out
	})
}

func testTranslator(t *testing.T, tests []testCase) {
	for _, test := range tests {
		payload, err := ioutil.ReadFile(filepath.Join(storage.ProjectRoot, test.input))
		if err != nil {
			t.Fatalf("test %q failed to read input file %q: %v", test.name, test.input, err)
		}

		var token dbGapIdToken
		if err := json.Unmarshal(payload, &token); err != nil {
			t.Fatalf("test %q failed to unmarshal ID token: %v", test.name, err)
		}

		id, err := test.translator.TestTranslator(convertToOIDCIDToken(token), payload)
		if err != nil {
			t.Fatalf("test %q failed during translation: %v", test.name, err)
		}

		expected, err := ioutil.ReadFile(filepath.Join(storage.ProjectRoot, test.expected))
		if err != nil {
			t.Fatalf("test %q failed to read expected output file %q: %v", test.name, test.expected, err)
		}
		var expectedID ga4gh.Identity
		if err := json.Unmarshal(expected, &expectedID); err != nil {
			t.Fatalf("test %q failed to unmarshal expected output %q: %v", test.name, test.expected, err)
		}
		test.cmpOptions = append(test.cmpOptions, sortClaims())
		if diff := cmp.Diff(expectedID, *id, test.cmpOptions...); diff != "" {
			t.Errorf("test %q returned diff (-want +got):\n%s", test.name, diff)
		}
	}
}
