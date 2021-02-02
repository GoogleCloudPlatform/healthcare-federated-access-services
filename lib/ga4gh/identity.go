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
	"net/url"
	"strings"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/errutil" /* copybara-comment: errutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/globalflags" /* copybara-comment: globalflags */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/strutil" /* copybara-comment: strutil */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
)

const (
	// AccessTokenVisaFormat represents an "Embedded Access Token" visa format.
	// See https://bit.ly/ga4gh-aai-profile#term-embedded-access-token.
	AccessTokenVisaFormat VisaFormat = "access_token"

	// DocumentVisaFormat represents an "Embedded Document Token" visa format.
	// See https://bit.ly/ga4gh-aai-profile#term-embedded-document-token.
	DocumentVisaFormat VisaFormat = "document"

	// UnspecifiedVisaFormat is used when the token cannot be read or is not available.
	UnspecifiedVisaFormat VisaFormat = ""
)

// VisaFormat indicates what GA4GH embedded token format is used for a visa.
// See  https://bit.ly/ga4gh-aai-profile#embedded-token-issued-by-embedded-token-issuer.
type VisaFormat string

// OldClaim represents a claim object as defined by GA4GH.
type OldClaim struct {
	Value       string                       `json:"value"`
	Source      string                       `json:"source"`
	Asserted    float64                      `json:"asserted,omitempty"`
	Expires     float64                      `json:"expires,omitempty"`
	Condition   map[string]OldClaimCondition `json:"condition,omitempty"`
	By          string                       `json:"by,omitempty"`
	Issuer      string                       `json:"issuer,omitempty"`
	VisaData    *VisaData                    `json:"-"`
	TokenFormat VisaFormat                   `json:"-"`
}

// OldClaimCondition represents a condition object as defined by GA4GH.
type OldClaimCondition struct {
	Value  []string `json:"value,omitempty"`
	Source []string `json:"source,omitempty"`
	By     []string `json:"by,omitempty"`
}

// VisaRejection is filled in by a policy engine to understand why a visa was rejected.
// Visas unrelated to the policy are not considered rejected unless they are not trusted.
type VisaRejection struct {
	Reason      string `json:"reason,omitempty"`
	Field       string `json:"field,omitempty"`
	Description string `json:"msg,omitempty"`
}

// RejectedVisa provides insight into why a policy engine is not making use of visas that
// are present within the passport.
type RejectedVisa struct {
	TokenFormat string        `json:"tokenFormat,omitempty"`
	Issuer      string        `json:"iss,omitempty"`
	Subject     string        `json:"sub,omitempty"`
	Assertion   Assertion     `json:"assertion,omitempty"`
	Rejection   VisaRejection `json:"rejection,omitempty"`
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
	TokenID          string                 `json:"tid,omitempty"`
	Nonce            string                 `json:"nonce,omitempty"`
	GA4GH            map[string][]OldClaim  `json:"-"` // do not emit
	RejectedVisas    []*RejectedVisa        `json:"-"` // do not emit
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
	Patient          string                 `json:"patient,omitempty"`  // SMART-on-FHIR
	FhirUser         string                 `json:"fhirUser,omitempty"` // SMART-on-FHIR
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
			if err := f(ctx, j, v.Data().Issuer, v.JKU()); err != nil {
				return fmt.Errorf("the verification of some LinkedIdentities visa failed: %v", err)
			}
		}

		visas = append(visas, v)
	}
	return CheckLinkedIDs(visas)
}

// RejectVisa adds a new RejectedVisa report to the identity (up to a maximum number of reports).
func (t *Identity) RejectVisa(visa *VisaData, format VisaFormat, reason, field, message string) {
	if len(t.RejectedVisas) > 20 {
		return
	}
	t.RejectedVisas = append(t.RejectedVisas, NewRejectedVisa(visa, format, reason, field, message))
}

// NewRejectedVisa creates a rejected visa information struct.
func NewRejectedVisa(visa *VisaData, format VisaFormat, reason, field, message string) *RejectedVisa {
	if visa == nil {
		visa = &VisaData{}
	}
	detail := VisaRejection{
		Reason:      reason,
		Field:       field,
		Description: message,
	}
	return &RejectedVisa{
		TokenFormat: string(format),
		Issuer:      visa.Issuer,
		Subject:     visa.Subject,
		Assertion:   visa.Assertion,
		Rejection:   detail,
	}
}

// VisasToOldClaims populates the GA4GH claim based on visas.
// Returns a map of visa types, each having a list of OldClaims for that type.
// TODO: use new policy engine instead when it becomes available.
func VisasToOldClaims(ctx context.Context, visas []VisaJWT, f JWTVerifier) (map[string][]OldClaim, []*RejectedVisa, error) {
	out := make(map[string][]OldClaim)
	var rejected []*RejectedVisa
	for i, j := range visas {
		// Skip this visa on validation errors such that a bad visa doesn't spoil the bunch.
		// But do return errors if the visas are not compatible with the old claim format.
		v, err := NewVisaFromJWT(VisaJWT(j))
		if err != nil {
			rejected = append(rejected, NewRejectedVisa(nil, UnspecifiedVisaFormat, "invalid_visa", "", fmt.Sprintf("cannot unpack visa %d", i)))
			continue
		}

		d := v.Data()
		if len(d.Issuer) == 0 {
			rejected = append(rejected, NewRejectedVisa(d, v.Format(), "iss_missing", "iss", "empty 'iss' field"))
			continue
		}

		if reject := checkViaJKU(v); reject != nil {
			rejected = append(rejected, reject)
			continue
		}

		if f != nil {
			if err := f(ctx, string(j), v.Data().Issuer, v.JKU()); err != nil {
				reason := errutil.ErrorReason(err)
				if len(reason) == 0 {
					reason = "verify_failed"
				}
				rejected = append(rejected, NewRejectedVisa(d, v.Format(), reason, "", err.Error()))
				continue
			}
		}

		var cond map[string]OldClaimCondition
		if len(d.Assertion.Conditions) > 0 {
			// Conditions on visas are not supported in non-experimental mode.
			if !globalflags.Experimental {
				rejected = append(rejected, NewRejectedVisa(d, v.Format(), "condition_not_supported", "visa.condition", "visa conditions not supported"))
				continue
			}
			cond, err = toOldClaimConditions(d.Assertion.Conditions)
			if err != nil {
				rejected = append(rejected, NewRejectedVisa(d, v.Format(), "condition_not_supported", "visa.condition", err.Error()))
				continue
			}
		}
		typ := string(d.Assertion.Type)
		values := splitVisaValues(d.Assertion.Value, d.Assertion.Type)
		for _, value := range values {
			c := OldClaim{
				Value:       value,
				Source:      string(d.Assertion.Source),
				Asserted:    float64(d.Assertion.Asserted),
				Expires:     float64(d.ExpiresAt),
				By:          string(d.Assertion.By),
				Issuer:      d.Issuer,
				VisaData:    d,
				TokenFormat: v.Format(),
				Condition:   cond,
			}
			out[typ] = append(out[typ], c)
		}
	}
	return out, rejected, nil
}

func checkViaJKU(v *Visa) *RejectedVisa {
	d := v.Data()

	openid := strutil.ContainsWord(string(d.Scope), "openid")

	if openid {
		if len(v.JKU()) > 0 {
			return NewRejectedVisa(d, v.Format(), "openid_jku", "", "visa has openid scope and jku")
		}

		return nil
	}
	if len(v.JKU()) == 0 {
		return NewRejectedVisa(d, v.Format(), "no_openid_no_jku", "", "visa does not have openid scope and jku")
	}

	issuerURL, err := url.Parse(d.Issuer)
	if err != nil {
		return NewRejectedVisa(d, v.Format(), "issuer_url_parse", "", fmt.Sprintf("issuer url parse failed: %v", err))
	}

	jkuURL, err := url.Parse(v.JKU())
	if err != nil {
		return NewRejectedVisa(d, v.Format(), "jku_url_parse", "", fmt.Sprintf("jku url parse failed: %v", err))
	}

	if jkuURL.Host != issuerURL.Host {
		return NewRejectedVisa(d, v.Format(), "jku_issuer_host", "", "jku does not have same host with visa issuer")
	}

	if !httputils.IsHTTPS(v.JKU()) && !httputils.IsLocalhost(v.JKU()) {
		return NewRejectedVisa(d, v.Format(), "jku_https", "", "jku does not use https")
	}

	return nil
}

func splitVisaValues(value Value, typ Type) []string {
	if typ != LinkedIdentities {
		return []string{string(value)}
	}
	return strings.Split(string(value), ";")
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

func toVisaRejectionProto(in VisaRejection) *cpb.VisaRejection {
	return &cpb.VisaRejection{
		Reason:      in.Reason,
		Field:       in.Field,
		Description: in.Description,
	}
}

// ToRejectedVisaProto convert RejectedVisa to proto.
func ToRejectedVisaProto(in *RejectedVisa) *cpb.RejectedVisa {
	if in == nil {
		return nil
	}
	return &cpb.RejectedVisa{
		TokenFormat: in.TokenFormat,
		Issuer:      in.Issuer,
		Subject:     in.Subject,
		Assertion:   toAssertionProto(in.Assertion),
		Rejection:   toVisaRejectionProto(in.Rejection),
	}
}
