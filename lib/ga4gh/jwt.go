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

	"github.com/dgrijalva/jwt-go"
)

// JWT contains the standard claims.
// TODO: check that []string for audiance works or we don't need it.
type JWT = jwt.StandardClaims

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
	_, parts, err := (&jwt.Parser{}).ParseUnverified(j, &JWT{})
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
