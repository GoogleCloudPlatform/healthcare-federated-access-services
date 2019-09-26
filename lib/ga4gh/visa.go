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

	glog "github.com/golang/glog"
	"github.com/dgrijalva/jwt-go"
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
	// JWT is embeded for standard JWT fields.
	JWT

	// Scope ...
	Scope string `json:"scope,omitempty"`

	// Claim contains the Visa Claim.
	Claim VClaim `json:"ga4gh_visa_v1,omitempty"`
}

// VClaim represents a GA4GH Passport Visa Object.
// A VClaim is an "Assertion".
type VClaim struct {
	Type       string     `json:"type,omitempty"`
	Value      string     `json:"value,omitempty"`
	Source     string     `json:"source,omitempty"`
	Asserted   int64      `json:"asserted,omitempty"`
	By         string     `json:"by,omitempty"`
	Conditions Conditions `json:"conditions,omitempty"`
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
func NewVisaFromData(d *VisaData, method SigningMethod, key *rsa.PrivateKey) (*Visa, error) {
	glog.V(1).Infof("NewVisaFromData(%+v,%T,%v)", d, method, key)
	j, err := visaJWTFromData(d, method, key)
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

func visaJWTFromData(d *VisaData, method SigningMethod, key *rsa.PrivateKey) (VisaJWT, error) {
	t := jwt.NewWithClaims(method, d)
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
