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
	"fmt"

	glog "github.com/golang/glog"
	"github.com/dgrijalva/jwt-go"
)

// Passport represents a GA4GH Passport.
type Passport struct {
	// jwt for the passport.
	jwt PassportJWT

	// data is unmarhsalled data contained in passport jwt.
	data *PassportData
}

// PassportJWT is a string containing a JWT Passport object.
type PassportJWT string

// PassportData is used to create a new Passport.
type PassportData struct {
	// JWT is embeded for standard JWT fields.
	JWT

	// Scope ...
	Scope string `json:"scope,omitempty"`

	// Visas contains the list of Visas for the Passport.
	Visas []*Visa `json:"ga4gh_passport_v1,omitempty"`
}

// NewPassportFromJWT creates a new Passport from a given JWT.
// Returns error if the JWT is not the JWT of a Passport.
// Does not verify the signature on the JWT.
func NewPassportFromJWT(j PassportJWT) (*Passport, error) {
	glog.V(1).Infof("NewPassportFromJWT(%+v)", j)
	d, err := passportDataFromJWT(j)
	if err != nil {
		return nil, err
	}
	return &Passport{
		jwt:  j,
		data: d,
	}, nil
}

// NewPassportFromData creates a new Passport.
func NewPassportFromData(d *PassportData, method SigningMethod, key *rsa.PrivateKey) (*Passport, error) {
	glog.V(1).Infof("NewPassportFromData(%+v,%T,%v)", d, key)
	j, err := passportJWTFromData(d, method, key)
	if err != nil {
		return nil, err
	}
	return &Passport{
		jwt:  j,
		data: d,
	}, nil
}

// Verify verifies the signature of the Passport using the provided public key.
// It does not verify the Visas in the passport.
func (p *Passport) Verify(key *rsa.PublicKey) error {
	f := func(token *jwt.Token) (interface{}, error) { return key, nil }
	_, err := jwt.Parse(string(p.jwt), f)
	return err
}

// JWT returns the JWT of a Passport.
func (p *Passport) JWT() PassportJWT {
	return p.jwt
}

// Data returns the data of a Passport.
func (p *Passport) Data() *PassportData {
	return p.data
}

// passportDataVisaJWT is internally used for marshaling and unmarshalling.
type passportDataVisaJWT struct {
	// JWT is embeded for standard JWT fields.
	JWT

	// Scope ...
	Scope string `json:"scope,omitempty"`

	// Visas contains the list of Visas for the Passport.
	Visas []VisaJWT `json:"ga4gh_passport_v1,omitempty"`
}

func passportJWTFromData(d *PassportData, method SigningMethod, key *rsa.PrivateKey) (PassportJWT, error) {
	t := jwt.NewWithClaims(method, toPassportDataWithVisaJWT(d))
	signed, err := t.SignedString(key)
	if err != nil {
		err = fmt.Errorf("SignedString() failed: %v", err)
		glog.V(1).Info(err)
		return "", err
	}
	return PassportJWT(signed), nil
}

func toPassportDataWithVisaJWT(d *PassportData) *passportDataVisaJWT {
	m := &passportDataVisaJWT{
		JWT:   d.JWT,
		Scope: d.Scope,
	}
	for _, v := range d.Visas {
		m.Visas = append(m.Visas, v.jwt)
	}
	return m
}

func passportDataFromJWT(j PassportJWT) (*PassportData, error) {
	m := &passportDataVisaJWT{}
	if _, _, err := (&jwt.Parser{}).ParseUnverified(string(j), m); err != nil {
		err = fmt.Errorf("ParseUnverified(%v) failed: %v", j, err)
		glog.V(1).Info(err)
		return nil, err
	}
	d, err := toPassportData(m)
	if err != nil {
		return nil, err
	}
	return d, nil
}

func toPassportData(m *passportDataVisaJWT) (*PassportData, error) {
	d := &PassportData{
		JWT:   m.JWT,
		Scope: m.Scope,
	}
	for _, j := range m.Visas {
		v, err := NewVisaFromJWT(VisaJWT(j))
		if err != nil {
			err = fmt.Errorf("NewVisaFromJWT(%v) failed: %v", j, err)
			glog.V(1).Info(err)
			return nil, err
		}
		d.Visas = append(d.Visas, v)
	}
	return d, nil
}
