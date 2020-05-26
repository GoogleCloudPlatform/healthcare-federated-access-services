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

// Package verifier provides a token verifier.
package verifier

import (
	"context"
	"strings"
	"time"

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/errutil" /* copybara-comment: errutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
)

// PassportVerifier verifies passport tokens.
type PassportVerifier struct {
	sig *oidcSigVerifier
	aud *passportAudienceVerifier
}

// Verify verifies signature, timestamp, issuer and audiences in passport token.
func (s *PassportVerifier) Verify(ctx context.Context, token string) error {
	return verify(ctx, s.sig, s.aud, token, "")
}

// VisaVerifier verifies visa tokens.
type VisaVerifier struct {
	sig sigVerifier
	aud *visaAudienceVerifier
}

// Verify signature, timestamp, issuer, jku and audiences in visa token.
func (s *VisaVerifier) Verify(ctx context.Context, token, jku string) error {
	if len(jku) > 0 {
		if _, ok := s.sig.(*jkuSigVerifier); !ok {
			return errutil.WithErrorReason(errVerifierInvalidType, status.Errorf(codes.Internal, "sigVerifier type must be oidc verifier"))
		}
	} else {
		if _, ok := s.sig.(*oidcSigVerifier); !ok {
			return errutil.WithErrorReason(errVerifierInvalidType, status.Errorf(codes.Internal, "sigVerifier type must be oidc verifier"))
		}
	}

	return verify(ctx, s.sig, s.aud, token, jku)
}

// AccessTokenVerifier verifies access tokens, used in lib/auth.
type AccessTokenVerifier struct {
	sig *oidcSigVerifier
	aud *accessTokenAudienceVerifier
}

// Verify verifies signature, timestamp, issuer and audiences in access token.
func (s *AccessTokenVerifier) Verify(ctx context.Context, token string, opt Option) error {
	return verify(ctx, s.sig, s.aud, token, "", opt)
}

// NewVisaVerifier creates a visa token verifier.
func NewVisaVerifier(ctx context.Context, issuer, jku, prefix string) (*VisaVerifier, error) {
	v := &VisaVerifier{
		aud: &visaAudienceVerifier{prefix: prefix},
	}
	if len(jku) > 0 {
		v.sig = newJKUJWTVerifier(ctx, issuer, jku)
		return v, nil
	}

	var err error
	v.sig, err = newOIDCSigVerifier(ctx, issuer)
	if err != nil {
		return nil, err
	}
	return v, nil
}

// NewPassportVerifier creates a passport token verifier.
func NewPassportVerifier(ctx context.Context, issuer, clientID string) (*PassportVerifier, error) {
	sig, err := newOIDCSigVerifier(ctx, issuer)
	if err != nil {
		return nil, err
	}

	return &PassportVerifier{
		sig: sig,
		aud: &passportAudienceVerifier{
			clientID: clientID,
		},
	}, nil
}

// NewAccessTokenVerifier creates a access token verifier.
func NewAccessTokenVerifier(ctx context.Context, issuer string) (*AccessTokenVerifier, error) {
	sig, err := newOIDCSigVerifier(ctx, issuer)
	if err != nil {
		return nil, err
	}

	return &AccessTokenVerifier{
		sig: sig,
		aud: &accessTokenAudienceVerifier{},
	}, nil
}

// sigVerifier is used to verify tokens.
type sigVerifier interface {
	VerifySig(ctx context.Context, token string) error
	Issuer() string
	JKU() string
}

// verify verifies the provided token.
func verify(ctx context.Context, sig sigVerifier, aud audienceVerifier, token, jku string, opts ...Option) error {
	d, err := ga4gh.NewStdClaimsFromJWT(token)
	if err != nil {
		return errutil.WithErrorReason(errParseFailed, status.Errorf(codes.Unauthenticated, "NewStdClaimsFromJWT() failed: %v", err))
	}

	if len(d.Subject) == 0 {
		return errutil.WithErrorReason(errSubMissing, status.Errorf(codes.Unauthenticated, "Issuer in token does not match issuer in sig"))
	}

	if normalizeIssuer(d.Issuer) != normalizeIssuer(sig.Issuer()) {
		return errutil.WithErrorReason(errIssuerNotMatch, status.Errorf(codes.Unauthenticated, "Issuer in token does not match issuer in sig"))
	}

	if jku != sig.JKU() {
		return errutil.WithErrorReason(errJKUNotMatch, status.Errorf(codes.Internal, "Issuer in token does not match issuer in sig"))
	}

	if err := aud.Verify(d, opts...); err != nil {
		return errutil.WithErrorReason(errInvalidAudience, status.Errorf(codes.Unauthenticated, "invalid aud claim: %v", err))
	}

	now := time.Now().Unix()
	if now > d.ExpiresAt {
		return errutil.WithErrorReason(errExpired, status.Errorf(codes.Unauthenticated, "token expired"))
	}

	if now < d.NotBefore {
		return errutil.WithErrorReason(errFutureToken, status.Errorf(codes.Unauthenticated, "future token: token is not valid yet"))
	}

	if now < d.IssuedAt {
		return errutil.WithErrorReason(errFutureToken, status.Errorf(codes.Unauthenticated, "future token: token used before issued"))
	}

	if err := sig.VerifySig(ctx, token); err != nil {
		return errutil.WithErrorReason(errInvalidSignature, status.Errorf(codes.Unauthenticated, "%v", err))
	}

	return nil
}

// normalizeIssuer ensure the issuer string does not have tailling slash.
func normalizeIssuer(issuer string) string {
	return strings.TrimSuffix(issuer, "/")
}

// Option for verifies tokens.
type Option interface {
	isOption()
}
