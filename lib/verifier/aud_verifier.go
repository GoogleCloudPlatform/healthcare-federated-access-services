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
	"fmt"
	"strings"

	"bitbucket.org/creachadair/stringset" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
)

type audienceVerifier interface {
	Verify(claims *ga4gh.StdClaims, opts ...Option) error
}

type passportAudienceVerifier struct {
	clientID string
}

func (s *passportAudienceVerifier) Verify(claims *ga4gh.StdClaims, opts ...Option) error {
	// passport requires audience must contain the given client claims.
	if stringset.Contains([]string(claims.Audience), s.clientID) {
		return nil
	}

	return fmt.Errorf("token does not have required audience")
}

type visaAudienceVerifier struct {
	prefix string
}

func (s *visaAudienceVerifier) Verify(claims *ga4gh.StdClaims, opts ...Option) error {
	// accept visa with empty audience
	if len(claims.Audience) == 0 {
		return nil
	}

	// Audience is set. Reject if given prefix is empty as we cannot ensure a match.
	if len(s.prefix) == 0 {
		return fmt.Errorf("token has audience but no prefix is set to allow")
	}

	// visa audience not empty, must have a audience has the given prefix
	for _, a := range claims.Audience {
		if strings.HasPrefix(a, s.prefix) {
			return nil
		}
	}

	return fmt.Errorf("token does not have an audience with given prefix")
}

type accessTokenAudienceVerifier struct {
}

type accessTokenOption struct {
	clientID string
	self     string
	useAzp   bool
}

func (s *accessTokenOption) isOption() {}

// AccessTokenOption for verifier aud/azp claims.
func AccessTokenOption(clientID, self string, useAzp bool) Option {
	return &accessTokenOption{
		clientID: clientID,
		self:     self,
		useAzp:   useAzp,
	}
}

func (s *accessTokenAudienceVerifier) Verify(claims *ga4gh.StdClaims, opts ...Option) error {
	var opt *accessTokenOption
	for _, o := range opts {
		if a, ok := o.(*accessTokenOption); ok {
			opt = a
			break
		}
	}
	if opt == nil {
		return fmt.Errorf("need accessTokenOption to verify aud/azp")
	}

	if len(claims.AuthorizedParty) == 0 && len(claims.Audience) == 0 {
		// Is a public token.
		return nil
	}

	if len(opt.self) > 0 {
		if opt.useAzp && opt.self == claims.AuthorizedParty {
			return nil
		}
		if stringset.Contains([]string(claims.Audience), opt.self) {
			return nil
		}
	}

	if opt.useAzp && opt.clientID == claims.AuthorizedParty {
		return nil
	}
	if stringset.Contains([]string(claims.Audience), opt.clientID) {
		return nil
	}

	return fmt.Errorf("token does not have a required audience or a required azp")
}
