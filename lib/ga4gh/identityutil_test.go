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
)

func TestHasUserinfoClaims(t *testing.T) {
	tests := []struct {
		name string
		id   *Identity
		want bool
	}{
		{
			name: "no user info claim in scp",
			id:   &Identity{Scp: []string{"aaa"}},
			want: false,
		},
		{
			name: "no user info claim in scope",
			id:   &Identity{Scope: "aaa"},
			want: false,
		},
		{
			name: "ga4gh claim in scp",
			id:   &Identity{Scp: []string{"ga4gh"}},
			want: true,
		},
		{
			name: "ga4gh claim in scope",
			id:   &Identity{Scope: "ga4gh"},
			want: true,
		},
		{
			name: "ga4gh_passport_v1 claim in scp",
			id:   &Identity{Scp: []string{"ga4gh_passport_v1"}},
			want: true,
		},
		{
			name: "ga4gh_passport_v1 claim in scope",
			id:   &Identity{Scope: "ga4gh_passport_v1"},
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

func TestTokenUserID(t *testing.T) {
	issuer := "http://example.com"
	maxLen := 25
	tests := []struct {
		name string
		id   *Identity
		want string
	}{
		{
			name: "sub without @",
			id: &Identity{
				Subject: "a",
				Issuer:  issuer + "/oidc",
			},
			want: "a|example.com",
		},
		{
			name: "sub with @",
			id: &Identity{
				Subject: "a@a.com",
				Issuer:  issuer + "/oidc",
			},
			want: "a@a.com|example.com",
		},
		{
			name: "return sub",
			id: &Identity{
				Subject: "a@example.com",
				Issuer:  issuer + "/oidc",
			},
			want: "a@example.com",
		},
		{
			name: "too long",
			id: &Identity{
				Subject: "12345678901234567890@example.com",
				Issuer:  issuer + "/oidc",
			},
			want: "12345678901234567890@exam",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := TokenUserID(tc.id, maxLen)
			if got != tc.want {
				t.Errorf("TokenUserID(%v, _) = %s, want %s", tc.id, got, tc.want)
			}
		})
	}
}
