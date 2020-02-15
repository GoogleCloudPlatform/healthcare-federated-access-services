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
	"strings"
	"time"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/globalflags" /* copybara-comment: globalflags */
)

// OldClaim represents a claim object as defined by GA4GH.
type OldClaim struct {
	Value     string                       `json:"value"`
	Source    string                       `json:"source"`
	Asserted  float64                      `json:"asserted,omitempty"`
	Expires   float64                      `json:"expires,omitempty"`
	Condition map[string]OldClaimCondition `json:"condition,omitempty"`
	By        string                       `json:"by,omitempty"`
	Issuer    string                       `json:"issuer,omitempty"`
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
	Subject          string                 `json:"sub,omitempty"`
	Issuer           string                 `json:"iss,omitempty"`
	IssuedAt         int64                  `json:"iat,omitempty"`
	NotBefore        int64                  `json:"nbf,omitempty"`
	Expiry           int64                  `json:"exp,omitempty"`
	Scope            string                 `json:"scope,omitempty"`
	Scp              []string               `json:"scp,omitempty"`
	Audiences        Audiences              `json:"aud,omitempty"`
	AuthorizedParty  string                 `json:"azp,omitempty"`
	ID               string                 `json:"jti,omitempty"`
	Nonce            string                 `json:"nonce,omitempty"`
	GA4GH            map[string][]OldClaim  `json:"ga4gh,omitempty"`
	IdentityProvider string                 `json:"idp,omitempty"`
	Identities       map[string][]string    `json:"identities,omitempty"`
	Username         string                 `json:"preferred_username,omitempty"`
	Email            string                 `json:"email,omitempty"`
	EmailVerified    bool                   `json:"email_verified,omitempty"`
	Name             string                 `json:"name,omitempty"`
	Nickname         string                 `json:"nickname,omitempty"`
	GivenName        string                 `json:"given_name,omitempty"`
	FamilyName       string                 `json:"family_name,omitempty"`
	MiddleName       string                 `json:"middle_name,omitempty"`
	ZoneInfo         string                 `json:"zoneinfo,omitempty"`
	Locale           string                 `json:"locale,omitempty"`
	Picture          string                 `json:"picture,omitempty"`
	Profile          string                 `json:"profile,omitempty"`
	Realm            string                 `json:"realm,omitempty"`
	VisaJWTs         []string               `json:"ga4gh_passport_v1,omitempty"`
	Extra            map[string]interface{} `json:"ext,omitempty"`
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
// Returns a map of visa types, each having a list of OldClaims for that type.
// TODO: use new policy engine instead when it becomes available.
func VisasToOldClaims(ctx context.Context, visas []VisaJWT, f JWTVerifier) (map[string][]OldClaim, int, error) {
	out := make(map[string][]OldClaim)
	skipped := 0
	for i, j := range visas {
		// Skip this visa on validation errors such that a bad visa doesn't spoil the bunch.
		// But do return errors if the visas are not compatible with the old claim format.
		v, err := NewVisaFromJWT(VisaJWT(j))
		if err != nil {
			skipped++
			continue
		}
		if f != nil {
			if err := f(ctx, string(j)); err != nil {
				skipped++
				continue
			}
		}
		d := v.Data()
		if len(d.Issuer) == 0 {
			skipped++
			continue
		}
		typ := string(d.Assertion.Type)
		c := OldClaim{
			Value:    string(d.Assertion.Value),
			Source:   string(d.Assertion.Source),
			Asserted: float64(d.Assertion.Asserted),
			Expires:  float64(d.ExpiresAt),
			By:       string(d.Assertion.By),
			Issuer:   d.Issuer,
		}
		if len(d.Assertion.Conditions) > 0 {
			// Conditions on visas are not supported in non-experimental mode.
			if !globalflags.Experimental {
				skipped++
				continue
			}
			c.Condition, err = toOldClaimConditions(d.Assertion.Conditions)
			if err != nil {
				return nil, skipped, fmt.Errorf("visa %d: %v", i, err)
			}
		}
		out[typ] = append(out[typ], c)
	}
	return out, skipped, nil
}

func toOldClaimConditions(conditions Conditions) (map[string]OldClaimCondition, error) {
	// Input is non-empty DNF: outer OR array with inner AND array.
	if len(conditions) > 1 {
		return nil, fmt.Errorf("unsupported visa condition: OR conditions are not supported")
	}
	out := make(map[string]OldClaimCondition)
	for _, cond := range conditions[0] {
		ctyp := string(cond.Type)
		oldCond, ok := out[ctyp]
		if ok {
			// Old format only allows one sub-condition per visa type, and this
			// sub-condition has already been populated, therefore the new
			// condition is not compatible with the old claim format.
			return nil, fmt.Errorf("unsupported visa condition: multiple conditions on the same visa type not supported")
		}
		if !ok {
			oldCond = OldClaimCondition{}
		}
		if len(cond.Value) > 0 {
			parts := strings.SplitN(string(cond.Value), ":", 2)
			if len(parts) != 2 || parts[0] != "const" {
				return nil, fmt.Errorf("unsupported visa condition: non-const condition on %q field", "value")
			}
			oldCond.Value = append(oldCond.Value, parts[1])
		}
		if len(cond.Source) > 0 {
			parts := strings.SplitN(string(cond.Source), ":", 2)
			if len(parts) != 2 || parts[0] != "const" {
				return nil, fmt.Errorf("unsupported visa condition: non-const condition on %q field", "source")
			}
			oldCond.Source = append(oldCond.Source, parts[1])
		}
		if len(cond.By) > 0 {
			parts := strings.SplitN(string(cond.By), ":", 2)
			if len(parts) != 2 || parts[0] != "const" {
				return nil, fmt.Errorf("unsupported visa condition: non-const condition on %q field", "by")
			}
			oldCond.By = append(oldCond.By, parts[1])
		}
		out[ctyp] = oldCond
	}
	return out, nil
}
