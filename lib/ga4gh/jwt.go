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
	"bytes"
	"encoding/json"

	glog "github.com/golang/glog" /* copybara-comment */
	"github.com/dgrijalva/jwt-go" /* copybara-comment */
)

// StdClaims contains the standard claims.
// We dupliacte this instead of just using jwt.StandardClaims because
// Audience can be a string array.
type StdClaims struct {
	Audience  Audiences `json:"aud,omitempty"`
	ExpiresAt int64     `json:"exp,omitempty"`
	ID        string    `json:"jti,omitempty"`
	IssuedAt  int64     `json:"iat,omitempty"`
	Issuer    string    `json:"iss,omitempty"`
	NotBefore int64     `json:"nbf,omitempty"`
	Subject   string    `json:"sub,omitempty"`
}

// Valid validates time based claims "exp, iat, nbf".
// There is no accounting for clock skew.
// As well, if any of the above claims are not in the token, it will still
// be considered a valid claim.
func (c StdClaims) Valid() error {
	// TODO: handle validation of c.Audience.
	tmp := &jwt.StandardClaims{
		ExpiresAt: c.ExpiresAt,
		Id:        c.ID,
		IssuedAt:  c.IssuedAt,
		Issuer:    c.Issuer,
		NotBefore: c.NotBefore,
		Subject:   c.Subject,
	}
	return tmp.Valid()
}

// SigningMethod for JWT.
type SigningMethod = jwt.SigningMethod

var (
	// RS256 is RSA. Used for signing/validation with private/public keys.
	// Expects *rsa.PrivateKey for signing and *rsa.PublicKey for validation.
	RS256 = jwt.SigningMethodRS256
)

var indent = "  "

// payloadFromJWT extracts and returns the decoded JSON of a JWT payload.
// Useful for logging and testing JSON format of payload.
// The JSON string uses "indent" for indention.
func payloadFromJWT(j string) (string, error) {
	_, parts, err := (&jwt.Parser{}).ParseUnverified(j, &StdClaims{})
	if err != nil {
		return "", err
	}
	encoded := parts[1]

	decoded, err := jwt.DecodeSegment(encoded)
	if err != nil {
		return "", err
	}

	payload := &bytes.Buffer{}
	if err := json.Indent(payload, decoded, "", indent); err != nil {
		return "", err
	}

	return payload.String(), nil
}

// jsontxt is used internally for transforming for cmp.Diff.
// Allowing getting stable diff in comparing JSON text strings.
// Example:
// diff := cmp.Diff(jsontxt(want), jsontxt(got), cmp.Transformer("", jsontxtCanonical))
type jsontxt string

func jsontxtCanonical(j jsontxt) string {
	var s interface{}
	if err := json.Unmarshal([]byte(j), &s); err != nil {
		glog.Fatalf("json.Unmarshal(%v) failed: %v", j, err)
	}
	d, err := json.Marshal(&s)
	if err != nil {
		glog.Fatalf("json.Marshal(%v) failed: %v", s, err)
	}
	c := &bytes.Buffer{}
	if err := json.Indent(c, d, "", indent); err != nil {
		glog.Fatalf("json.Indent(%v,%v,%v,%v) failed: %v", c, d, "", indent, err)
	}
	return c.String()
}

// NewStdClaimsFromJWT extracts StdClaims from a serialized JWT token.
func NewStdClaimsFromJWT(token string) (*StdClaims, error) {
	d := &StdClaims{}
	if _, _, err := (&jwt.Parser{}).ParseUnverified(token, d); err != nil {
		return nil, err
	}
	return d, nil
}
