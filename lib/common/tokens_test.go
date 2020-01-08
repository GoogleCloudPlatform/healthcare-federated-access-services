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

package common

import (
	"testing"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
)

func TestHasUserinfoClaims(t *testing.T) {
	tests := []struct {
		name string
		id   *ga4gh.Identity
		want bool
	}{
		{
			name: "no user info claim in scp",
			id:   &ga4gh.Identity{Scp: []string{"aaa"}},
			want: false,
		},
		{
			name: "no user info claim in scope",
			id:   &ga4gh.Identity{Scope: "aaa"},
			want: false,
		},
		{
			name: "ga4gh claim in scp",
			id:   &ga4gh.Identity{Scp: []string{"ga4gh"}},
			want: true,
		},
		{
			name: "ga4gh claim in scope",
			id:   &ga4gh.Identity{Scope: "ga4gh"},
			want: true,
		},
		{
			name: "ga4gh_passport_v1 claim in scp",
			id:   &ga4gh.Identity{Scp: []string{"ga4gh_passport_v1"}},
			want: true,
		},
		{
			name: "ga4gh_passport_v1 claim in scope",
			id:   &ga4gh.Identity{Scope: "ga4gh_passport_v1"},
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if HasUserinfoClaims(tc.id) != tc.want {
				t.Errorf("HasUserinfoClaims() wants %v", tc.want)
			}
		})
	}
}
