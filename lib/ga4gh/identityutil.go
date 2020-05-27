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
	"net/url"
	"strings"

	"gopkg.in/square/go-jose.v2" /* copybara-comment */
	"gopkg.in/square/go-jose.v2/jwt" /* copybara-comment */
)

// userID returns an user identifier that specifies a subject within an issuer.
func userID(subject, issuer string, maxLength int) string {
	domain := "unknown"
	if u, err := url.Parse(issuer); err == nil {
		domain = u.Hostname()
	}
	parts := strings.SplitN(subject, "@", 2)
	if len(parts) < 2 || parts[1] != domain {
		subject += "|" + domain
	}
	// UserID is also used as a description in some cases, and that has a max length
	// that a long domain name may exceed.
	if len(subject) > maxLength {
		subject = subject[0:maxLength]
	}
	return subject
}

// TokenUserID returns an user identifier for a given token.
func TokenUserID(token *Identity, maxLength int) string {
	return userID(token.Subject, token.Issuer, maxLength)
}

// VerifyTokenWithKey verifies the signature of a token given a public key.
func VerifyTokenWithKey(publicKey *rsa.PublicKey, tok string) error {
	jws, err := jose.ParseSigned(tok)
	if err != nil {
		return fmt.Errorf("parsing ID token %v", err)
	}
	_, err = jws.Verify(publicKey)
	return err
}

// ConvertTokenToIdentityUnsafe unsafely converts a token to an identity.
func ConvertTokenToIdentityUnsafe(tok string) (*Identity, error) {
	parsed, err := jwt.ParseSigned(tok)
	if err != nil {
		return nil, fmt.Errorf("parsing JWT: %v", err)
	}
	var id Identity
	if err := parsed.UnsafeClaimsWithoutVerification(&id); err != nil {
		return nil, fmt.Errorf("extracting base claims without verifying signature: %v", err)
	}
	return &id, nil
}

// HasUserinfoClaims checks if /userinfo endpoint needs to be called to fetch additional claims for
// a particular identity.
func HasUserinfoClaims(id *Identity) bool {
	var scopes []string
	// Hydra is using "scp" claims in access token.
	if len(id.Scp) > 0 {
		scopes = id.Scp
	} else {
		scopes = strings.Split(id.Scope, " ")
	}

	for _, scope := range scopes {
		if scope == "ga4gh" || scope == "ga4gh_passport_v1" || scope == "identities" {
			return true
		}
	}
	return false
}
