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
	"golang.org/x/oauth2" /* copybara-comment */
	"github.com/coreos/go-oidc" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/errutil" /* copybara-comment: errutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
)

// oidcUserinfoVerifier use /userinfo to verify the access token and fetch ID information.
type oidcUserinfoVerifier struct {
	issuer   string
	provider *oidc.Provider
}

// newOIDCUserinfoVerifier creates a new oidc token verifier using userinfo.
func newOIDCUserinfoVerifier(ctx context.Context, issuer string) (*oidcUserinfoVerifier, error) {
	p, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, errutil.WithErrorReason(errCreateVerifierFailed, status.Errorf(codes.Unavailable, "create oidc failed: %v", err))
	}

	return &oidcUserinfoVerifier{
		issuer:   issuer,
		provider: p,
	}, nil
}

func (s *oidcUserinfoVerifier) ExtractClaims(ctx context.Context, token string, claims interface{}) (*ga4gh.StdClaims, error) {
	userinfo, err := s.provider.UserInfo(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}))
	if err != nil {
		return nil, errutil.WithErrorReason(errUserinfoInvalidToken, status.Errorf(codes.Unauthenticated, "userinfo return failed: %v", err))
	}

	d := &ga4gh.StdClaims{}
	if err := userinfo.Claims(d); err != nil {
		return nil, err
	}

	if claims != nil {
		if err := userinfo.Claims(claims); err != nil {
			return nil, err
		}
	}

	// iss claim maybe empty from /userinfo response
	if len(d.Issuer) == 0 {
		d.Issuer = s.Issuer()
	}

	return d, nil
}

// VerifySig is a no-op because PreviewClaimsBeforeVerification already has performed the verification steps on the IdP before returning the response.
func (s *oidcUserinfoVerifier) VerifySig(ctx context.Context, token string) error {
	return nil
}

func (s *oidcUserinfoVerifier) Issuer() string {
	return s.issuer
}
