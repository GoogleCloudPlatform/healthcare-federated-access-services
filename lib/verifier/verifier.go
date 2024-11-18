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

	"google3/third_party/golang/github_com/go_jose/go_jose/v/v3/jwt/jwt"
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/errutil" /* copybara-comment: errutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
)

// PassportVerifier verifies passport tokens.
type PassportVerifier struct {
	tok *oidcJwtSigVerifier
	aud *passportAudienceVerifier
}

// Verify verifies signature, timestamp, issuer and audiences in passport token.
func (s *PassportVerifier) Verify(ctx context.Context, token string) error {
	return verify(ctx, s.tok, s.aud, token, nil)
}

// VisaVerifier verifies visa tokens.
type VisaVerifier struct {
	tok extractClaimsAndVerifyToken
	aud *visaAudienceVerifier
}

// Verify signature, timestamp, issuer, jku and audiences in visa token.
func (s *VisaVerifier) Verify(ctx context.Context, token, jku string) error {
	if len(jku) > 0 {
		if _, ok := s.tok.(*jkuVisaSigVerifier); !ok {
			return errutil.WithErrorReason(errVerifierInvalidType, status.Errorf(codes.Internal, "extractClaimsAndVerifyToken type must be an oidc verifier"))
		}
	} else {
		if _, ok := s.tok.(*oidcJwtSigVerifier); !ok {
			return errutil.WithErrorReason(errVerifierInvalidType, status.Errorf(codes.Internal, "extractClaimsAndVerifyToken type must be an oidc verifier"))
		}
	}

	return verify(ctx, s.tok, s.aud, token, nil)
}

// JWTAccessTokenVerifier verifies jwt access tokens, used in lib/auth.
type JWTAccessTokenVerifier struct {
	tok *oidcJwtSigVerifier
	aud *accessTokenAudienceVerifier
}

// Verify verifies signature, timestamp, issuer and audiences in access tok.
func (s *JWTAccessTokenVerifier) Verify(ctx context.Context, token string, claims any, opt Option) error {
	return verify(ctx, s.tok, s.aud, token, claims, opt)
}

// UserinfoAccesssTokenVerifier verifies access tokens with userinfo endpoint, used in lib/auth.
type UserinfoAccesssTokenVerifier struct {
	tok *oidcOpaqueUserinfoVerifier
	aud *accessTokenAudienceVerifier
}

// Verify verifies signature, timestamp, issuer and audiences of access token with userinfo.
func (s *UserinfoAccesssTokenVerifier) Verify(ctx context.Context, token string, claims any, opt Option) error {
	return verify(ctx, s.tok, s.aud, token, claims, opt)
}

// NewVisaVerifier creates a visa token verifier.
func NewVisaVerifier(ctx context.Context, issuer, jku, prefix string) (*VisaVerifier, error) {
	v := &VisaVerifier{
		aud: &visaAudienceVerifier{prefix: prefix},
	}
	if len(jku) > 0 {
		v.tok = newJkuVisaSigVerifier(ctx, issuer, jku)
		return v, nil
	}

	var err error
	v.tok, err = newOIDCSigVerifier(ctx, issuer)
	if err != nil {
		return nil, err
	}
	return v, nil
}

// NewPassportVerifier creates a passport token verifier.
func NewPassportVerifier(ctx context.Context, issuer, clientID string) (*PassportVerifier, error) {
	tok, err := newOIDCSigVerifier(ctx, issuer)
	if err != nil {
		return nil, err
	}

	return &PassportVerifier{
		tok: tok,
		aud: &passportAudienceVerifier{
			clientID: clientID,
		},
	}, nil
}

// AccessTokenVerifier verifies jwt access tokens or access token to userinfo, used in lib/auth.
type AccessTokenVerifier interface {
	Verify(ctx context.Context, token string, claims any, opt Option) error
}

// NewAccessTokenVerifier creates a access tok verifier.
func NewAccessTokenVerifier(ctx context.Context, issuer string, useUserinfoVerifier bool) (AccessTokenVerifier, error) {
	if useUserinfoVerifier {
		tok, err := newOIDCUserinfoVerifier(ctx, issuer)
		if err != nil {
			return nil, err
		}
		return &UserinfoAccesssTokenVerifier{
			tok: tok,
			aud: &accessTokenAudienceVerifier{},
		}, nil
	}

	tok, err := newOIDCSigVerifier(ctx, issuer)
	if err != nil {
		return nil, err
	}

	return &JWTAccessTokenVerifier{
		tok: tok,
		aud: &accessTokenAudienceVerifier{},
	}, nil
}

// extractClaimsAndVerifyToken is used to verify tokens.
type extractClaimsAndVerifyToken interface {
	// PreviewClaimsBeforeVerification from the given tok, will also extracts to custom claim object if claims passed in.
	// Claims will be unsafe for jwt token, and claims will be safe if fetched from the userinfo endpoint.
	// This function need to be called before VerifySig().
	PreviewClaimsBeforeVerification(ctx context.Context, token string, claims any) (*ga4gh.StdClaims, error)
	// VerifySig of the access tok, it will be empty if not jwt tok.
	VerifySig(ctx context.Context, token string) error
	// Issuer the wanted issuer of the tok.
	Issuer() string
}

// verify verifies the provided token.
func verify(ctx context.Context, tokenVerifier extractClaimsAndVerifyToken, aud audienceVerifier, token string, claims any, opts ...Option) error {
	d, err := tokenVerifier.PreviewClaimsBeforeVerification(ctx, token, claims)
	if err != nil {
		return err
	}

	if len(d.Subject) == 0 {
		return errutil.WithErrorReason(errSubMissing, status.Errorf(codes.Unauthenticated, "Issuer in tok does not match issuer in tokenVerifier"))
	}

	if normalizeIssuer(d.Issuer) != normalizeIssuer(tokenVerifier.Issuer()) {
		return errutil.WithErrorReason(errIssuerNotMatch, status.Errorf(codes.Unauthenticated, "Issuer in tok does not match issuer in tokenVerifier"))
	}

	if err := aud.Verify(d, opts...); err != nil {
		return errutil.WithErrorReason(errInvalidAudience, status.Errorf(codes.Unauthenticated, "invalid aud claim: %v", err))
	}

	now := time.Now().Unix()
	if now > d.ExpiresAt {
		return errutil.WithErrorReason(errExpired, status.Errorf(codes.Unauthenticated, "tok expired"))
	}

	if now < d.NotBefore {
		return errutil.WithErrorReason(errFutureToken, status.Errorf(codes.Unauthenticated, "future tok: tok is not valid yet"))
	}

	if now < d.IssuedAt {
		return errutil.WithErrorReason(errFutureToken, status.Errorf(codes.Unauthenticated, "future tok: tok used before issued"))
	}

	if err := tokenVerifier.VerifySig(ctx, token); err != nil {
		return errutil.WithErrorReason(errInvalidSignature, status.Errorf(codes.Unauthenticated, "%v", err))
	}

	return nil
}

// normalizeIssuer ensure the issuer string does not have trailing slash.
func normalizeIssuer(issuer string) string {
	return strings.TrimSuffix(issuer, "/")
}

// Option for verifies tokens.
type Option interface {
	isOption()
}

// unsafeClaimsFromJWTToken extracts custom claims from jwt body.
func unsafeClaimsFromJWTToken(token string, obj any) error {
	tok, err := jwt.ParseSigned(token)
	if err != nil {
		return errutil.WithErrorReason(errParseFailed, status.Errorf(codes.Unauthenticated, "ParseSigned() failed: %v", err))
	}

	if err := tok.UnsafeClaimsWithoutVerification(obj); err != nil {
		return errutil.WithErrorReason(errParseFailed, status.Errorf(codes.Unauthenticated, "UnsafeClaimsWithoutVerification() failed: %v", err))
	}

	return nil
}
