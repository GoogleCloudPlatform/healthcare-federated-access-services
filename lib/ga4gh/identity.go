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
	"context"
	"fmt"
	"time"
)

// OldClaim represents a claim object as defined by GA4GH.
type OldClaim struct {
	Value     string                       `json:"value"`
	Source    string                       `json:"source"`
	Asserted  float64                      `json:"asserted,omitempty"`
	Expires   float64                      `json:"expires,omitempty"`
	Condition map[string]OldClaimCondition `json:"condition,omitempty"`
	By        string                       `json:"by,omitempty"`
}

// OldClaimCondition represents a condition object as defined by GA4GH.
type OldClaimCondition struct {
	Value  []string `json:"value,omitempty"`
	Source []string `json:"source,omitempty"`
	By     []string `json:"by,omitempty"`
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
	Realm            string                `json:"realm,omitempty"`
	VisaJWTs         []string              `json:"ga4gh_passport_v1,omitempty"`
}

// Valid implements dgrijalva/jwt-go Claims interface. This will be called when using
// dgrijalva/jwt-go parse. This validates exp, iat, nbf in token.
func (t *Identity) Valid() error {
	return t.Validate("")
}

// Validate returns an error if the Identity does not pass basic checks.
func (t *Identity) Validate(clientID string) error {
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

	// TODO: check non-empty clientID against t.Audiences

	return nil
}

// CheckIdentityAllVisasLinked checks if the Visas inside the identity are linked.
// Verifies all Visas of type LinkedIdentities.
// If JWTVerifier is not nil, will call f to verify LinkedIdentities Visas.
// If JWTVerifier is nil, verification is skipped.
func CheckIdentityAllVisasLinked(ctx context.Context, i *Identity, f JWTVerifier) error {
	var visas []*Visa
	for _, j := range i.VisaJWTs {
		v, err := NewVisaFromJWT(VisaJWT(j))
		if err != nil {
			return err
		}

		if f != nil && v.Data().Assertion.Type == LinkedIdentities {
			if err := f(ctx, j); err != nil {
				return fmt.Errorf("the verification of some LinkedIdentities visa failed: %v", err)
			}
		}

		visas = append(visas, v)
	}
	return CheckLinkedIDs(visas)
}

// VisasToOldClaims populates the GA4GH claim based on visas.
// TODO: use new policy engine instead when it becomes available.
func VisasToOldClaims(vs []VisaJWT) map[string][]OldClaim {
	out := make(map[string][]OldClaim)
	for _, j := range vs {
		// Skip this visa on any errors such that a bad visa doesn't spoil the bunch.
		v, err := NewVisaFromJWT(VisaJWT(j))
		if err != nil {
			continue
		}
		d := v.Data()
		typ := string(d.Assertion.Type)
		c := OldClaim{
			Value:    string(d.Assertion.Value),
			Source:   string(d.Assertion.Source),
			Asserted: float64(d.Assertion.Asserted),
			Expires:  float64(d.ExpiresAt),
			By:       string(d.Assertion.By),
		}
		if len(d.Assertion.Conditions) > 0 {
			c.Condition = toOldClaimConditions(d.Assertion.Conditions)
		}
		out[typ] = append(out[typ], c)
	}
	return out
}

func toOldClaimConditions(input Conditions) map[string]OldClaimCondition {
	out := make(map[string]OldClaimCondition)
	for _, cor := range input {
		for _, cand := range cor {
			ctyp := string(cand.Type)
			oldCond, ok := out[ctyp]
			if !ok {
				oldCond = OldClaimCondition{}
			}
			if len(cand.Value) > 0 {
				oldCond.Value = append(oldCond.Value, string(cand.Value))
			}
			if len(cand.Source) > 0 {
				oldCond.Source = append(oldCond.Source, string(cand.Source))
			}
			if len(cand.By) > 0 {
				oldCond.By = append(oldCond.By, string(cand.By))
			}
			out[ctyp] = oldCond
		}
	}
	return out
}
