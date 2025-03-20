// Copyright 2020 Google LLC.
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

// Package localsign contains a jwt signer use jose/jwt.
package localsign

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v4" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */
)

// Signer can sign jwt.
type Signer struct {
	key  jose.JSONWebKey
	pri  *rsa.PrivateKey
	algo jose.SignatureAlgorithm
}

// New RS256 Signer with given key.
func New(k *testkeys.Key) *Signer {
	return &Signer{
		key: jose.JSONWebKey{
			Key:       k.Public,
			Algorithm: string(jose.RS256),
			Use:       "sig",
			KeyID:     k.ID,
		},
		pri:  k.Private,
		algo: jose.RS256,
	}
}

// NewRS384Signer use RS384 to sign jwt
func NewRS384Signer(k *testkeys.Key) *Signer {
	return &Signer{
		key: jose.JSONWebKey{
			Key:       k.Public,
			Algorithm: string(jose.RS384),
			Use:       "sig",
			KeyID:     k.ID,
		},
		pri:  k.Private,
		algo: jose.RS384,
	}
}

// PublicKeys in signer.
func (s *Signer) PublicKeys() *jose.JSONWebKeySet {
	return &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{s.key},
	}
}

// SignJWT signs the given claims return the jwt string.
func (s *Signer) SignJWT(ctx context.Context, claims any, header map[string]string) (string, error) {
	key := jose.SigningKey{
		Algorithm: s.algo,
		Key:       s.pri,
	}

	opt := &jose.SignerOptions{}
	opt.WithType("JWT")

	if header == nil {
		header = map[string]string{}
	}
	header["kid"] = s.key.KeyID
	for k, v := range header {
		opt.WithHeader(jose.HeaderKey(k), v)
	}

	signer, err := jose.NewSigner(key, opt)
	if err != nil {
		return "", fmt.Errorf("failed to create signer:" + err.Error())
	}

	b, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	res, err := signer.Sign(b)
	if err != nil {
		return "", err
	}

	return res.CompactSerialize()
}
