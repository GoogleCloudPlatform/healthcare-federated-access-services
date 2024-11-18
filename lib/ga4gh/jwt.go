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
	"fmt"

	"google3/third_party/golang/github_com/go_jose/go_jose/v/v3/jwt/jwt"
)

var (
	// JWTEmptyJKU is for visa issuers who do not wish to set a "jku" header.
	// See https://tools.ietf.org/html/rfc7515#section-4.1.2 for details.
	JWTEmptyJKU = ""
)

// StdClaims contains the standard claims.
// We duplicate this instead of just using jwt.StandardClaims because
// Audience can be a string array.
type StdClaims struct {
	Audience        Audiences `json:"aud,omitempty"`
	AuthorizedParty string    `json:"azp,omitempty"`
	ExpiresAt       int64     `json:"exp,omitempty"`
	ID              string    `json:"jti,omitempty"`
	IssuedAt        int64     `json:"iat,omitempty"`
	Issuer          string    `json:"iss,omitempty"`
	NotBefore       int64     `json:"nbf,omitempty"`
	Subject         string    `json:"sub,omitempty"`
}

// NewStdClaimsFromJWT extracts StdClaims from a serialized JWT token.
func NewStdClaimsFromJWT(token string) (*StdClaims, error) {
	d := &StdClaims{}
	tok, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, fmt.Errorf("ParseSigned() failed: %v", err)
	}

	if err := tok.UnsafeClaimsWithoutVerification(d); err != nil {
		return nil, fmt.Errorf("UnsafeClaimsWithoutVerification() failed: %v", err)
	}
	return d, nil
}
