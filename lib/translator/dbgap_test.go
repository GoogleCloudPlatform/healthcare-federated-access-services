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
	"testing"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys"
)

const (
	translatorTestNow = 1560000000
)

func (s *DbGapTranslator) TestTranslator(token *oidc.IDToken, payload []byte) (*ga4gh.Identity, error) {
	var claims dbGapClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	return s.translateToken(token, claims, time.Unix(translatorTestNow, 0))
}

func TestDbGap(t *testing.T) {
	translator, err := NewDbGapTranslator("", "http://example.com/oidc", testkeys.Keys[testkeys.VisaIssuer0].PrivateStr)
	if err != nil {
		t.Fatalf("failed to create a new dbGap translator: %v", err)
	}
	tests := []testCase{
		{
			name:       "successful translation",
			input:      "testdata/passports/dbgap.json",
			translator: translator,
			expected:   "testdata/passports/dbgap_to_ga4gh.json",
		},
		{
			name:       "translation of a passport with no datasets",
			input:      "testdata/passports/dbgap_no_datasets.json",
			translator: translator,
			expected:   "testdata/passports/dbgap_no_datasets_to_ga4gh.json",
		},
	}
	testTranslator(t, tests)
}
