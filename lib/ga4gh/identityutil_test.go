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
			name: "no user info claim in scope",
			id:   &Identity{Scope: "aaa"},
			want: false,
		},
		{
			name: "ga4gh claim in scope",
			id:   &Identity{Scope: "ga4gh"},
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

func TestIsAudience(t *testing.T) {
	clientID := "cid"
	selfURL := "http://example.com"
	tests := []struct {
		name     string
		id       *Identity
		clientID string
		selfURL  string
		want     bool
	}{
		{
			name: "public token",
			id: &Identity{
				Audiences:       []string{},
				AuthorizedParty: "",
			},
			clientID: clientID,
			selfURL:  selfURL,
			want:     true,
		},
		{
			name: "client id in aud",
			id: &Identity{
				Audiences:       []string{"something_else", clientID},
				AuthorizedParty: "",
			},
			clientID: clientID,
			selfURL:  selfURL,
			want:     true,
		},
		{
			name: "client id in azp",
			id: &Identity{
				Audiences:       []string{"something_else"},
				AuthorizedParty: clientID,
			},
			clientID: clientID,
			selfURL:  selfURL,
			want:     true,
		},
		{
			name: "no client id",
			id: &Identity{
				Audiences:       []string{"something_else", selfURL},
				AuthorizedParty: selfURL,
			},
			clientID: "",
			selfURL:  selfURL,
			want:     false,
		},
		{
			name: "self in aud",
			id: &Identity{
				Audiences:       []string{"something_else", selfURL},
				AuthorizedParty: "",
			},
			clientID: clientID,
			selfURL:  selfURL,
			want:     true,
		},
		{
			name: "self in azp",
			id: &Identity{
				Audiences:       []string{"something_else"},
				AuthorizedParty: selfURL,
			},
			clientID: clientID,
			selfURL:  selfURL,
			want:     true,
		},
		{
			name: "not match",
			id: &Identity{
				Audiences:       []string{"something_else"},
				AuthorizedParty: "something_else2",
			},
			clientID: clientID,
			selfURL:  selfURL,
			want:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if IsAudience(tc.id, tc.clientID, tc.selfURL) != tc.want {
				t.Errorf("IsAudience(%v, %s, %s) want %v", tc.id, tc.clientID, tc.selfURL, tc.want)
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
