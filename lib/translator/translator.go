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

package translator

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"golang.org/x/oauth2" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
)

// Translator is used to convert an HTTP bearer authorization string that is _not_ in
// the normal Identity format into an Identity.  This is useful when
// interoperating with systems that do not yet provide a GA4GH identity.
type Translator interface {
	TranslateToken(ctx context.Context, auth string) (*ga4gh.Identity, error)
}

// FetchUserinfoClaims calls the /userinfo endpoint of an issuer to fetch additional claims.
func FetchUserinfoClaims(ctx context.Context, id *ga4gh.Identity, tok string, translator Translator) (*ga4gh.Identity, error) {
	// Issue a Get request to the issuer's /userinfo endpoint.
	// TODO: use JWKS to discover the /userinfo endpoint.
	contentType, userInfo, err := issueGetRequest(ctx, strings.TrimSuffix(id.Issuer, "/")+"/userinfo", tok)
	if err != nil {
		return nil, err
	}

	// Convert the /userinfo response to an identity based on the content type.
	var userinfo ga4gh.Identity
	switch contentType {
	case "application/json":
		if err := json.Unmarshal(userInfo, &userinfo); err != nil {
			return nil, fmt.Errorf("inspecting user info claims: %v", err)
		}
	case "application/jwt":
		tok, err := translator.TranslateToken(ctx, string(userInfo))
		if err != nil {
			return nil, fmt.Errorf("inspecting signed user info claims: %v", err)
		}
		if tok.Issuer != id.Issuer {
			return nil, fmt.Errorf("incorrect issuer in user info claims: got: %q, expected: %q", tok.Issuer, id.Issuer)
		}
		userinfo = *tok
	default:
		return nil, fmt.Errorf("unsupported content type returned by /userinfo endpoint: %q", contentType)
	}

	mergeIdentityWithUserinfo(id, &userinfo)

	return id, nil
}

func mergeIdentityWithUserinfo(id *ga4gh.Identity, userinfo *ga4gh.Identity) {
	if len(id.Subject) == 0 {
		id.Subject = userinfo.Subject
	}
	if len(id.Issuer) == 0 {
		id.Issuer = userinfo.Issuer
	}
	if id.IssuedAt == 0 {
		id.IssuedAt = userinfo.IssuedAt
	}
	if id.NotBefore == 0 {
		id.NotBefore = userinfo.NotBefore
	}
	if id.Expiry == 0 {
		id.Expiry = userinfo.Expiry
	}
	if len(id.Scope) == 0 {
		id.Scope = userinfo.Scope
	}
	if len(id.Scp) == 0 {
		id.Scp = userinfo.Scp
	}
	if len(id.Audiences) == 0 {
		id.Audiences = userinfo.Audiences
	}
	if len(id.AuthorizedParty) == 0 {
		id.AuthorizedParty = userinfo.AuthorizedParty
	}
	if len(id.ID) == 0 {
		id.ID = userinfo.ID
	}
	if len(id.Nonce) == 0 {
		id.Nonce = userinfo.Nonce
	}
	if len(id.GA4GH) == 0 {
		id.GA4GH = userinfo.GA4GH
	}
	if len(id.IdentityProvider) == 0 {
		id.IdentityProvider = userinfo.IdentityProvider
	}
	if len(id.Identities) == 0 {
		id.Identities = userinfo.Identities
	}
	if len(id.Username) == 0 {
		id.Username = userinfo.Username
	}
	if len(id.Email) == 0 {
		id.Email = userinfo.Email
	}
	if len(id.Name) == 0 {
		id.Name = userinfo.Name
	}
	if len(id.Nickname) == 0 {
		id.Nickname = userinfo.Nickname
	}
	if len(id.GivenName) == 0 {
		id.GivenName = userinfo.GivenName
	}
	if len(id.FamilyName) == 0 {
		id.FamilyName = userinfo.FamilyName
	}
	if len(id.MiddleName) == 0 {
		id.MiddleName = userinfo.MiddleName
	}
	if len(id.ZoneInfo) == 0 {
		id.ZoneInfo = userinfo.ZoneInfo
	}
	if len(id.Locale) == 0 {
		id.Locale = userinfo.Locale
	}
	if len(id.Picture) == 0 {
		id.Picture = userinfo.Picture
	}
	if len(id.Profile) == 0 {
		id.Profile = userinfo.Profile
	}
	if len(id.Realm) == 0 {
		id.Realm = userinfo.Realm
	}
	if len(id.VisaJWTs) == 0 {
		id.VisaJWTs = userinfo.VisaJWTs
	}
}

func issueGetRequest(ctx context.Context, url, acTok string) (string, []byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", []byte{}, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Add("Authorization", "Bearer "+acTok)

	client := http.DefaultClient
	if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		client = c
	}
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return "", []byte{}, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", []byte{}, fmt.Errorf("response returned error code %q: %q", resp.Status, resp.Body)
	}

	contentType := strings.ToLower(strings.Split(resp.Header.Get("Content-Type"), ";")[0])
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", []byte{}, fmt.Errorf("failed to ready response body: %v", err)
	}
	return contentType, body, nil
}
