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

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/coreos/go-oidc" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/errutil" /* copybara-comment: errutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
)

type jkuSigVerifier struct {
	issuer string
	jku    string
	keyset oidc.KeySet
}

// newJKUJWTVerifier creates a extractClaimsAndVerifySignature for jku jwt tokens.
func newJKUJWTVerifier(ctx context.Context, issuer, jku string) *jkuSigVerifier {
	return &jkuSigVerifier{
		issuer: issuer,
		jku:    jku,
		keyset: oidc.NewRemoteKeySet(ctx, jku),
	}
}

func (s *jkuSigVerifier) ExtractClaims(ctx context.Context, token string, claims interface{}) (*ga4gh.StdClaims, error) {
	// extracts the unsafe claims here to allow following step to validate issue, timestamp.
	d, err := ga4gh.NewStdClaimsFromJWT(token)
	if err != nil {
		return nil, errutil.WithErrorReason(errParseFailed, status.Errorf(codes.Unauthenticated, "NewStdClaimsFromJWT() failed: %v", err))
	}

	if claims != nil {
		if err := unsafeClaimsFromJWTToken(token, claims); err != nil {
			 return nil, err
		}
	}

	return d, nil
}

func (s *jkuSigVerifier) VerifySig(ctx context.Context, token string) error {
	_, err := s.keyset.VerifySignature(ctx, token)
	return err
}

func (s *jkuSigVerifier) Issuer() string {
	return s.issuer
}
