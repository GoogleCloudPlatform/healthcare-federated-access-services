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

	"github.com/go-jose/go-jose/v4" /* copybara-comment */
	"github.com/go-jose/go-jose/v4/jwt" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/kms" /* copybara-comment: kms */

	glog "github.com/golang/glog" /* copybara-comment */
	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
)

// Visa represents a GA4GH Passport Visa.
// A Visa is a "Signed Assertion".
type Visa struct {
	// jwt for the visa.
	jwt VisaJWT

	// "jku" visa header (see https://tools.ietf.org/html/rfc7515#section-4.1.2).
	// This header changes the visa type as per the GA4GH AAI Profile
	// (https://github.com/ga4gh/data-security/blob/master/AAI/AAIConnectProfile.md#term-embedded-document-token).
	jku string

	// data is unmarhsalled data contained in visa jwt.
	data *VisaData
}

// VisaJWT is a JWT object containing a GA4GH Visa.
type VisaJWT string

// VisaData is used for creating a new visa.
type VisaData struct {
	// StdClaims is embeded for standard JWT claims.
	StdClaims

	// Scope for the Visa.
	// http://bit.ly/ga4gh-aai-profile#ga4gh-jwt-format
	Scope Scope `json:"scope,omitempty"`

	// Assertion contains the Visa Assertion.
	Assertion Assertion `json:"ga4gh_visa_v1,omitempty"`
}

// NewVisaFromJWT creates a new Visa from a given JWT.
// Returns error if the JWT is not the JWT of a Visa.
// Does not verify the signature on the JWT.
func NewVisaFromJWT(j VisaJWT) (*Visa, error) {
	glog.V(1).Infof("NewVisaFromJWT(%+v)", j)
	d, jku, err := visaDataFromJWT(j)
	if err != nil {
		return nil, err
	}
	return &Visa{
		jwt:  j,
		jku:  jku,
		data: d,
	}, nil
}

// NewVisaFromData creates a new Visa.
//
// keyID identifies the key used by issuer to sign the JWT.
// Visit the issuer's JWKS endpoint to obtain the keys and find the public key corresponding to the keyID.
// To find the issuer's JWKS endpoint:
//
//	If openid scope exists in the Visa, visit "[issuer]/.well-known/openid-configuration"
//	Else if "jku" exists in JWT header, use the "jku" value.
//	Otherwise, the Visa cannot be verified.
//
// See https://bit.ly/ga4gh-aai-profile#embedded-token-issued-by-embedded-token-issuer
func NewVisaFromData(ctx context.Context, d *VisaData, jku string, signer kms.Signer) (*Visa, error) {
	j, err := visaJWTFromData(ctx, d, jku, signer)
	if err != nil {
		return nil, err
	}
	return &Visa{
		jwt:  j,
		jku:  jku,
		data: d,
	}, nil
}

// JKU returns the JKU header of a Visa.
func (v *Visa) JKU() string {
	return v.jku
}

// JWT returns the JWT of a Visa.
func (v *Visa) JWT() VisaJWT {
	return v.jwt
}

// Data returns the data of a Visa.
func (v *Visa) Data() *VisaData {
	return v.data
}

// AssertionProto returns the visa assertion in common proto (cpb.Assertion) format.
func (v *Visa) AssertionProto() *cpb.Assertion {
	a := toAssertionProto(v.data.Assertion)
	a.Exp = v.Data().ExpiresAt
	return a
}

// Format returns the VisaFormat (i.e. embedded token format) for the visa.
func (v *Visa) Format() VisaFormat {
	if len(v.jku) == 0 {
		return AccessTokenVisaFormat
	}
	return DocumentVisaFormat
}

func visaJWTFromData(ctx context.Context, d *VisaData, jku string, signer kms.Signer) (VisaJWT, error) {
	header := map[string]string{}
	if jku != JWTEmptyJKU {
		header[jwtHeaderJKU] = jku
	}
	signed, err := signer.SignJWT(ctx, d, header)
	if err != nil {
		return "", err
	}
	return VisaJWT(signed), nil
}

// visaDataFromJWT converts a JWT token to data elements.
// Returns: visa payload data, the "jku" header string (if any), and error.
func visaDataFromJWT(j VisaJWT) (*VisaData, string, error) {
	d := &VisaData{}

	tok, err := jwt.ParseSigned(string(j), []jose.SignatureAlgorithm{
		jose.HS256,
		jose.HS384,
		jose.HS512,
		jose.RS256,
		jose.RS384,
		jose.RS512,
		jose.ES256,
		jose.ES384,
		jose.ES512,
		jose.PS256,
		jose.PS384,
		jose.PS512,
		jose.EdDSA,
	})
	if err != nil {
		return nil, JWTEmptyJKU, fmt.Errorf("ParseSigned() failed: %v", err)
	}

	if err := tok.UnsafeClaimsWithoutVerification(d); err != nil {
		return nil, JWTEmptyJKU, fmt.Errorf("UnsafeClaimsWithoutVerification() failed: %v", err)
	}

	if len(tok.Headers) != 1 {
		return nil, JWTEmptyJKU, fmt.Errorf("jwt invalid header")
	}

	if len(tok.Headers[0].ExtraHeaders) == 0 {
		return d, JWTEmptyJKU, nil
	}

	jku, ok := tok.Headers[0].ExtraHeaders["jku"]
	if !ok {
		return d, JWTEmptyJKU, nil
	}
	str, ok := jku.(string)
	if !ok {
		return nil, JWTEmptyJKU, fmt.Errorf("casting jku to string failed")
	}
	return d, str, nil
}

// MustVisaDataFromJWT converts a VisaJWT to VisaData.
// Crashes if VisaJWT cannot be parsed.
// Useful for writing tests: cmp.Transformer("", ga4gh.VisaJWTTransform)
// DO NOT use in non-test code.
// TODO: move to a testutil package.
func MustVisaDataFromJWT(j VisaJWT) *VisaData {
	d, _, err := visaDataFromJWT(j)
	if err != nil {
		glog.Fatalf("visaDataFromJWT(%v) failed: %v", j, err)
	}
	return d
}
