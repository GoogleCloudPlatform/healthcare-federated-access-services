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
)

const (
	jwtHeaderJKU = "jku"
)

// Passport represents a GA4GH Passport.
// http://bit.ly/ga4gh-passport-v1#overview
type Passport struct {
	// Access is the Access Token for the Passport.
	Access *Access

	// Visas contains the list of Visas for the Passport.
	Visas []*Visa `json:"ga4gh_passport_v1,omitempty"`
}

// Access represents a GA4GH Access Token.
// http://bit.ly/ga4gh-passport-v1#overview
type Access struct {
	// jwt for the Access.
	jwt AccessJWT

	// data is unmarhsalled data contained in access jwt.
	data *AccessData
}

// AccessJWT is a string containing a JWT Access object.
type AccessJWT string

// AccessData is used to create a new Access.
type AccessData struct {
	// StdClaims is embeded for standard JWT claims.
	StdClaims

	// Scope ...
	Scope string `json:"scope,omitempty"`

	// TODO: Replace identities with LinkedIdentities visas.
	Identities map[string][]string `json:"identities,omitempty"`

	Patient string `json:"patient,omitempty"`

	// FhirUser is the SMART-on-FHIR principal identity.
	FhirUser string `json:"fhirUser,omitempty"`
}

// NewAccessFromJWT creates a new Access from a given JWT.
// Returns error if the JWT is not the JWT of a Access.
// Does not verify the signature on the JWT.
func NewAccessFromJWT(j AccessJWT) (*Access, error) {
	glog.V(1).Info("NewAccessFromJWT()")
	d, err := accessDataFromJWT(j)
	if err != nil {
		return nil, err
	}
	return &Access{
		jwt:  j,
		data: d,
	}, nil
}

// NewAccessFromData creates a new Access.
//
// keyID identifies the key used by issuer to sign the JWT.
// Visit the issuer's JWKS endpoint to obtain the keys and find the public key corresponding to the keyID.
// To find the issuer's JWKS endpoint, visit "[issuer]/.well-known/openid-configuration"
// "jku" in JWT header is not allowed for Access.
func NewAccessFromData(ctx context.Context, d *AccessData, signer kms.Signer) (*Access, error) {
	glog.V(1).Info("NewAccessFromData()")
	j, err := accessJWTFromData(ctx, d, signer)
	if err != nil {
		return nil, err
	}
	return &Access{
		jwt:  j,
		data: d,
	}, nil
}

// JWT returns the JWT of a Access.
func (p *Access) JWT() AccessJWT {
	return p.jwt
}

// Data returns the data of a Access.
func (p *Access) Data() *AccessData {
	return p.data
}

// accessDataVisaJWT is internally used for marshaling and unmarshalling.
type accessDataVisaJWT struct {
	// StdClaims is embeded for standard JWT claims.
	StdClaims

	// Scope ...
	Scope string `json:"scope,omitempty"`

	// TODO: Replace identities with LinkedIdentities visas.
	Identities map[string][]string `json:"identities,omitempty"`
}

func accessJWTFromData(ctx context.Context, d *AccessData, signer kms.Signer) (AccessJWT, error) {
	signed, err := signer.SignJWT(ctx, d, nil)

	if err != nil {
		err = fmt.Errorf("SignJWT() failed: %v", err)
		glog.V(1).Info(err)
		return "", err
	}

	return AccessJWT(signed), nil
}

func toAccessDataWithVisaJWT(d *AccessData) *accessDataVisaJWT {
	m := &accessDataVisaJWT{
		StdClaims:  d.StdClaims,
		Scope:      d.Scope,
		Identities: d.Identities,
	}
	return m
}

func accessDataFromJWT(j AccessJWT) (*AccessData, error) {
	m := &accessDataVisaJWT{}

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
		return nil, fmt.Errorf("ParseSigned() failed: %v", err)
	}

	if err := tok.UnsafeClaimsWithoutVerification(m); err != nil {
		return nil, fmt.Errorf("UnsafeClaimsWithoutVerification() failed: %v", err)
	}

	d, err := toAccessData(m)
	if err != nil {
		return nil, err
	}
	return d, nil
}

func toAccessData(m *accessDataVisaJWT) (*AccessData, error) {
	d := &AccessData{
		StdClaims:  m.StdClaims,
		Scope:      m.Scope,
		Identities: m.Identities,
	}
	return d, nil
}
