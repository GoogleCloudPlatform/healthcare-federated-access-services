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

package verifier

import (
	"testing"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
)

func TestPassportAudienceVerifier_Verify(t *testing.T) {
	tests := []struct {
		name   string
		claims *ga4gh.StdClaims
	}{
		{
			name: "aud = client claims",
			claims: &ga4gh.StdClaims{
				Audience: []string{client},
			},
		},
		{
			name: "aud includes client claims",
			claims: &ga4gh.StdClaims{
				Audience: []string{"a", client},
			},
		},
	}

	v := &passportAudienceVerifier{clientID: client}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Verify(tc.claims)
			if err != nil {
				t.Errorf("Verify() failed: %v", err)
			}
		})
	}
}

func TestPassportAudienceVerifier_Verify_Fail(t *testing.T) {
	tests := []struct {
		name   string
		claims *ga4gh.StdClaims
	}{
		{
			name:   "empty",
			claims: &ga4gh.StdClaims{},
		},
		{
			name: "not include",
			claims: &ga4gh.StdClaims{
				Audience:        []string{"a"},
				AuthorizedParty: "a",
			},
		},
	}

	v := &passportAudienceVerifier{clientID: client}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Verify(tc.claims)
			if err == nil {
				t.Errorf("Verify() wants err")
			}
		})
	}
}

func TestVisaAudienceVerifier_Verify(t *testing.T) {
	tests := []struct {
		name     string
		audience ga4gh.Audiences
		prefix   string
	}{
		{
			name:     "includes prefix",
			audience: []string{"aaa", "example.com/aaa"},
			prefix:   "example.com",
		},
		{
			name:     "empty aud",
			audience: []string{},
			prefix:   "example.com",
		},
		{
			name:     "empty prefix",
			audience: []string{},
			prefix:   "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := &visaAudienceVerifier{prefix: tc.prefix}
			err := v.Verify(&ga4gh.StdClaims{Audience: tc.audience})
			if err != nil {
				t.Errorf("Verify() failed: %v", err)
			}
		})
	}
}

func TestVisaAudienceVerifier_Verify_Fail(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
	}{
		{
			name:   "aud not match prefix",
			prefix: "example.com",
		},
		{
			name:   "empty prefix",
			prefix: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := &visaAudienceVerifier{prefix: tc.prefix}

			err := v.Verify(&ga4gh.StdClaims{Audience: []string{"a"}})
			if err == nil {
				t.Errorf("Verify() wants err")
			}
		})
	}
}

func TestAccessTokenAudienceVerifier_Verify(t *testing.T) {
	clientID := "cid"
	selfURL := "http://example.com"
	option := AccessTokenOption(clientID, selfURL, true)
	tests := []struct {
		name   string
		claims *ga4gh.StdClaims
		opt    Option
		pass   bool
	}{
		{
			name: "public token",
			claims: &ga4gh.StdClaims{
				Audience:        []string{},
				AuthorizedParty: "",
			},
			opt:  option,
			pass: true,
		},
		{
			name: "client claims in aud",
			claims: &ga4gh.StdClaims{
				Audience:        []string{"something_else", clientID},
				AuthorizedParty: "",
			},
			opt:  option,
			pass: true,
		},
		{
			name: "client claims in azp",
			claims: &ga4gh.StdClaims{
				Audience:        []string{"something_else"},
				AuthorizedParty: clientID,
			},
			opt:  option,
			pass: true,
		},
		{
			name: "self in aud",
			claims: &ga4gh.StdClaims{
				Audience:        []string{"something_else", selfURL},
				AuthorizedParty: "",
			},
			opt:  option,
			pass: true,
		},
		{
			name: "self in azp",
			claims: &ga4gh.StdClaims{
				Audience:        []string{"something_else"},
				AuthorizedParty: selfURL,
			},
			opt:  option,
			pass: true,
		},
		{
			name: "not match",
			claims: &ga4gh.StdClaims{
				Audience:        []string{"something_else"},
				AuthorizedParty: "something_else2",
			},
			opt:  option,
			pass: false,
		},
		{
			name: "not match: no selfURL",
			claims: &ga4gh.StdClaims{
				Audience:        []string{"something_else"},
				AuthorizedParty: "something_else2",
			},
			opt:  AccessTokenOption(clientID, "", true),
			pass: false,
		},
		{
			name: "not match: not use azp",
			claims: &ga4gh.StdClaims{
				Audience:        []string{"something_else"},
				AuthorizedParty: clientID,
			},
			opt:  AccessTokenOption(clientID, "", false),
			pass: false,
		},
		{
			name: "no opt",
			claims: &ga4gh.StdClaims{
				Audience:        []string{},
				AuthorizedParty: "",
			},
			opt:  nil,
			pass: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := &accessTokenAudienceVerifier{}
			err := v.Verify(tc.claims, tc.opt)
			got := err == nil
			if got != tc.pass {
				t.Errorf("Verify() = %v wants %v", err, tc.pass)
			}
		})
	}
}
