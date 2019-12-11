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
	"crypto/rsa"

	glog "github.com/golang/glog" /* copybara-comment */
	"github.com/dgrijalva/jwt-go" /* copybara-comment */
	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
)

// Visa represents a GA4GH Passport Visa.
// A Visa is a "Signed Assertion".
type Visa struct {
	// jwt for the visa.
	jwt VisaJWT

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
	d, err := visaDataFromJWT(j)
	if err != nil {
		return nil, err
	}
	return &Visa{
		jwt:  j,
		data: d,
	}, nil
}

// NewVisaFromData creates a new Visa.
//
// keyID identifies the key used by issuer to sign the JWT.
// Visit the issuer's JWKS endpoint to obtain the keys and find the public key corresponding to the keyID.
// To find the issuer's JWKS endpoint:
//   If openid scope exists in the Visa, visit "[issuer]/.well-known/openid-configuration"
//   Else if "jku" exists in JWT header, use the "jku" value.
//   Otherwise, the Visa cannot be verified.
// See https://bit.ly/ga4gh-aai-profile#embedded-token-issued-by-embedded-token-issuer
func NewVisaFromData(d *VisaData, method SigningMethod, key *rsa.PrivateKey, keyID string) (*Visa, error) {
	glog.V(1).Infof("NewVisaFromData(%+v,%T,%v)", d, method, key)
	j, err := visaJWTFromData(d, method, key, keyID)
	if err != nil {
		return nil, err
	}
	return &Visa{
		jwt:  j,
		data: d,
	}, nil
}

// Verify verifies the signature of the Visa using the given public key.
func (v *Visa) Verify(key *rsa.PublicKey) error {
	f := func(token *jwt.Token) (interface{}, error) { return key, nil }
	_, err := jwt.Parse(string(v.jwt), f)
	return err
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

func visaJWTFromData(d *VisaData, method SigningMethod, key *rsa.PrivateKey, keyID string) (VisaJWT, error) {
	t := jwt.NewWithClaims(method, d)
	t.Header[jwtHeaderKeyID] = keyID
	signed, err := t.SignedString(key)
	if err != nil {
		return "", err
	}
	return VisaJWT(signed), nil
}

func visaDataFromJWT(j VisaJWT) (*VisaData, error) {
	d := &VisaData{}
	if _, _, err := (&jwt.Parser{}).ParseUnverified(string(j), d); err != nil {
		return nil, err
	}
	return d, nil
}

// MustVisaDataFromJWT converts a VisaJWT to VisaData.
// Crashes if VisaJWT cannot be parsed.
// Useful for writing tests: cmp.Transformer("", ga4gh.VisaJWTTransform)
// DO NOT use in non-test code.
// TODO: move to a testutil package.
func MustVisaDataFromJWT(j VisaJWT) *VisaData {
	d, err := visaDataFromJWT(j)
	if err != nil {
		glog.Fatalf("visaDataFromJWT(%v) failed: %v", j, err)
	}
	return d
}
