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

package verifier

import (
	"context"

	"github.com/coreos/go-oidc" /* copybara-comment */
)

type jkuSigVerifier struct {
	issuer string
	jku    string
	keyset oidc.KeySet
}

// newJKUJWTVerifier creates a sigVerifier for jku jwt tokens.
func newJKUJWTVerifier(ctx context.Context, issuer, jku string) *jkuSigVerifier {
	return &jkuSigVerifier{
		issuer: issuer,
		jku:    jku,
		keyset: oidc.NewRemoteKeySet(ctx, jku),
	}
}

func (s *jkuSigVerifier) VerifySig(ctx context.Context, token string) error {
	_, err := s.keyset.VerifySignature(ctx, token)
	return err
}

func (s *jkuSigVerifier) Issuer() string {
	return s.issuer
}

func (s *jkuSigVerifier) JKU() string {
	return s.jku
}
