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
	"encoding/json"
	"fmt"
	"time"
)

const (
	// OldClaimAffiliationAndRole as per the Researcher Identity RFC.
	OldClaimAffiliationAndRole = "AffiliationAndRole"
	// OldClaimAcceptedTermsAndPolicies as per the Researcher Identity RFC.
	OldClaimAcceptedTermsAndPolicies = "AcceptedTermsAndPolicies"
	// OldClaimResearcherStatus as per the Researcher Identity RFC.
	OldClaimResearcherStatus = "ResearcherStatus"
	// OldClaimControlledAccessGrants as per the Researcher Identity RFC.
	OldClaimControlledAccessGrants = "ControlledAccessGrants"
)

// OldClaim represents a claim object as defined by GA4GH.
type OldClaim struct {
	Value     string                    `json:"value"`
	Source    string                    `json:"source"`
	Asserted  float64                   `json:"asserted,omitempty"`
	Expires   float64                   `json:"expires,omitempty"`
	Condition map[string]OldClaimCondition `json:"condition,omitempty"`
	By        string                    `json:"by,omitempty"`
}

// OldClaimCondition represents a condition object as defined by GA4GH.
type OldClaimCondition struct {
	Value  []string `json:"value,omitempty"`
	Source []string `json:"source,omitempty"`
	By     []string `json:"by,omitempty"`
}

// Audiences is "aud" field in jwt. In oidc spec, "aud" can be single string
// or array of string.
type Audiences struct {
	Audiences []string
}

// MarshalJSON marshal Audiences to array of string in json.
func (a *Audiences) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.Audiences)
}

// UnmarshalJSON unmarshal string or array of string in json to []string in go.
func (a *Audiences) UnmarshalJSON(bytes []byte) error {
	// Try string first.
	var s string
	err := json.Unmarshal(bytes, &s)
	if err == nil {
		a.Audiences = []string{s}
		return nil
	}

	// Try []string if unmarshal to string failed.
	return json.Unmarshal(bytes, &a.Audiences)
}

// Identity is a GA4GH identity as described by the Data Use and Researcher
// Identity stream.
type Identity struct {
	Subject          string                `json:"sub,omitempty"`
	Issuer           string                `json:"iss,omitempty"`
	IssuedAt         int64                 `json:"iat,omitempty"`
	NotBefore        int64                 `json:"nbf,omitempty"`
	Expiry           int64                 `json:"exp,omitempty"`
	Scope            string                `json:"scope,omitempty"`
	Audiences        Audiences             `json:"aud,omitempty"`
	AuthorizedParty  string                `json:"azp,omitempty"`
	ID               string                `json:"jti,omitempty"`
	Nonce            string                `json:"nonce,omitempty"`
	GA4GH            map[string][]OldClaim `json:"ga4gh,omitempty"`
	UserinfoClaims   []string              `json:"ga4gh_userinfo_claims"`
	IdentityProvider string                `json:"idp,omitempty"`
	Identities       map[string][]string   `json:"identities,omitempty"`
	Username         string                `json:"preferred_username,omitempty"`
	Email            string                `json:"email,omitempty"`
	EmailVerified    bool                  `json:"email_verified,omitempty"`
	Name             string                `json:"name,omitempty"`
	Nickname         string                `json:"nickname,omitempty"`
	GivenName        string                `json:"given_name,omitempty"`
	FamilyName       string                `json:"family_name,omitempty"`
	MiddleName       string                `json:"middle_name,omitempty"`
	ZoneInfo         string                `json:"zoneinfo,omitempty"`
	Locale           string                `json:"locale,omitempty"`
	Picture          string                `json:"picture,omitempty"`
	Profile          string                `json:"profile,omitempty"`
}

// Valid implements dgrijalva/jwt-go Claims interface. This will be called when using
// dgrijalva/jwt-go parse. This validates exp, iat, nbf in token.
func (t *Identity) Valid() error {
	now := time.Now().Unix()

	if now > t.Expiry {
		return fmt.Errorf("token is expired")
	}

	if now < t.IssuedAt {
		return fmt.Errorf("token used before issued")
	}

	if now < t.NotBefore {
		return fmt.Errorf("token is not valid yet")
	}

	return nil
}
