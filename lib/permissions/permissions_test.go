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

package permissions

import (
	"testing"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */
)

const (
	testConfigPath = "testdata/config"
	testService    = "permissions"
)

func TestAdmin(t *testing.T) {
	fs := storage.NewMemoryStorage(testService, testConfigPath)

	perm := New(fs)

	type adminTest struct {
		name             string
		subject          string
		identities       []string
		linkedIdentities string
		want             bool
	}

	tests := []adminTest{
		{
			name:             "admin user in subject",
			subject:          "admin@example.com",
			identities:       []string{},
			linkedIdentities: "",
			want:             true,
		},
		{
			name:             "admin user in identities",
			subject:          "no_admin@example.com",
			identities:       []string{"admin@example.com"},
			linkedIdentities: "",
			want:             true,
		},
		{
			name:             "admin user in linkedIdentities",
			subject:          "no_admin@example.com",
			identities:       []string{},
			linkedIdentities: "admin@example.com,https://example.com/oidc",
			want:             true,
		},
		{
			name:             "not admin user",
			subject:          "no_admin@example.com",
			identities:       []string{},
			linkedIdentities: "",
			want:             false,
		},
		{
			name:             "admin expired",
			subject:          "expire_admin@example.com",
			identities:       []string{},
			linkedIdentities: "",
			want:             false,
		},
		{
			name:             "admin expired",
			subject:          "expire_admin@example.com",
			identities:       []string{},
			linkedIdentities: "",
			want:             false,
		},
		{
			name:             "admin expired",
			subject:          "expire_admin@example.com",
			identities:       []string{},
			linkedIdentities: "",
			want:             false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			identities := make(map[string][]string)
			for _, identity := range tc.identities {
				identities[identity] = []string{}
			}
			d := &ga4gh.VisaData{
				Assertion: ga4gh.Assertion{
					Type:  ga4gh.LinkedIdentities,
					Value: ga4gh.Value(tc.linkedIdentities),
				},
			}
			v, err := ga4gh.NewVisaFromData(d, ga4gh.JWTEmptyJKU, ga4gh.RS256, testkeys.Keys[testkeys.VisaIssuer0].Private, string(testkeys.VisaIssuer0))
			if err != nil {
				t.Fatalf("ga4gh.NewVisaFromData failed: %v", err)
			}

			id := &ga4gh.Identity{
				Subject:    tc.subject,
				Identities: identities,
				VisaJWTs:   []string{string(v.JWT())},
			}
			isAdmin, err := perm.CheckAdmin(id)
			if err != nil {
				t.Fatalf("CheckAdmin() failed: %v", err)
			}
			if isAdmin != tc.want {
				t.Errorf("CheckAdmin() = %v, wants %v", isAdmin, tc.want)
			}
		})
	}
}
