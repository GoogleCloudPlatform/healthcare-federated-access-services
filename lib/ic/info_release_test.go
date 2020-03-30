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

package ic

import (
	"testing"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */
)

func Test_toInformationReleasePageArgs(t *testing.T) {
	d := &ga4gh.VisaData{
		StdClaims: ga4gh.StdClaims{
			Issuer: "fake-passport-issuer",
		},
		Assertion: ga4gh.Assertion{
			By:     "by",
			Type:   "type",
			Value:  "value",
			Source: "source",
		},
	}
	v, err := ga4gh.NewVisaFromData(d, "", ga4gh.RS256, testkeys.Default.Private, testkeys.Default.ID)
	if err != nil {
		t.Fatalf("NewVisaFromData(_) failed: %v", err)
	}
	id := &ga4gh.Identity{
		Subject: "sub",
		Name:    "name-1",
		Email:   "a@example.com",
		Identities: map[string][]string{
			"a@example.org": nil,
		},
		VisaJWTs: []string{string(v.JWT())},
	}

	t.Run("default", func(t *testing.T) {
		got := toInformationReleasePageArgs(id, "state", "client", "openid offline ga4gh_passport_v1 profile identities account_admin")
		want := &informationReleasePageArgs{
			ApplicationName: "client",
			Scope:           "openid offline ga4gh_passport_v1 profile identities account_admin",
			AssetDir:        "/identity/static",
			ID:              "sub",
			Offline:         true,
			Information: map[string][]*informationItem{
				"Permission": []*informationItem{
					{
						Title: "account_admin",
						Value: "manage (modify) this account",
						ID:    "account_admin",
					},
				},
				"Profile": []*informationItem{
					{Title: "Name", Value: "name-1", ID: "profile.name"},
					{Title: "Email", Value: "a@example.com", ID: "profile.email"},
					{Title: "Identities", Value: "a@example.org", ID: "identities"},
				},
				"Visas": []*informationItem{
					{
						Title: "type@source",
						Value: "value",
						ID:    "eyJ0eXBlIjoidHlwZSIsInNvdXJjZSI6InNvdXJjZSIsImJ5IjoiYnkiLCJpc3MiOiJmYWtlLXBhc3Nwb3J0LWlzc3VlciJ9",
					},
				},
			},
			State: "state",
		}
		if d := cmp.Diff(want, got); len(d) != 0 {
			t.Errorf("toInformationReleasePageArgs (-want, +got): %s", d)
		}
	})

	t.Run("less scope", func(t *testing.T) {
		got := toInformationReleasePageArgs(id, "state", "client", "openid offline")
		want := &informationReleasePageArgs{
			ApplicationName: "client",
			Scope:           "openid offline",
			AssetDir:        "/identity/static",
			ID:              "sub",
			Offline:         true,
			Information:     map[string][]*informationItem{},
			State:           "state",
		}
		if d := cmp.Diff(want, got); len(d) != 0 {
			t.Errorf("toInformationReleasePageArgs (-want, +got): %s", d)
		}
	})

	t.Run("less info", func(t *testing.T) {
		id := &ga4gh.Identity{
			Subject: "sub",
		}
		got := toInformationReleasePageArgs(id, "state", "client", "openid offline ga4gh_passport_v1 profile identities")
		want := &informationReleasePageArgs{
			ApplicationName: "client",
			Scope:           "openid offline ga4gh_passport_v1 profile identities",
			AssetDir:        "/identity/static",
			ID:              "sub",
			Offline:         true,
			Information:     map[string][]*informationItem{},
			State:           "state",
		}
		if d := cmp.Diff(want, got); len(d) != 0 {
			t.Errorf("toInformationReleasePageArgs (-want, +got): %s", d)
		}
	})
}
