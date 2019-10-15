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

	"golang.org/x/oauth2"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh"
)

// Translator is used to convert an HTTP bearer authorization string that is _not_ in
// the normal Identity format into an Identity.  This is useful when
// interoperating with systems that do not yet provide a GA4GH identity.
type Translator interface {
	TranslateToken(ctx context.Context, auth string) (*ga4gh.Identity, error)
}

// FetchUserinfoClaims calls the /userinfo endpoint of an issuer to fetch additional claims.
func FetchUserinfoClaims(ctx context.Context, tok, issuer, subject string, translator Translator) (*ga4gh.Identity, error) {
	// Issue a Get request to the issuer's /userinfo endpoint.
	// TODO: use JWKS to discover the /userinfo endpoint.
	contentType, userInfo, err := issueGetRequest(ctx, strings.TrimSuffix(issuer, "/")+"/userinfo", tok)
	if err != nil {
		return nil, err
	}

	// Convert the /userinfo response to an identity based on the content type.
	var id ga4gh.Identity
	switch contentType {
	case "application/json":
		if err := json.Unmarshal(userInfo, &id); err != nil {
			return nil, fmt.Errorf("inspecting user info claims: %v", err)
		}
	case "application/jwt":
		tok, err := translator.TranslateToken(ctx, string(userInfo))
		if err != nil {
			return nil, fmt.Errorf("inspecting signed user info claims: %v", err)
		}
		if tok.Issuer != issuer {
			return nil, fmt.Errorf("incorrect issuer in user info claims: got: %q, expected: %q", id.Issuer, issuer)
		}
		id = *tok
	default:
		return nil, fmt.Errorf("unsupported content type returned by /userinfo endpoint: %q", contentType)
	}
	if len(subject) > 0 && subject != id.Subject {
		return nil, fmt.Errorf("incorrect subject in user info claims: got: %q, expected: %q", id.Subject, subject)
	}

	return &id, nil
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
