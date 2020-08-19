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

package ic

import (
	"testing"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"github.com/gorilla/mux" /* copybara-comment */
	"bitbucket.org/creachadair/stringset" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/hydraproxy" /* copybara-comment: hydraproxy */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakeoidcissuer" /* copybara-comment: fakeoidcissuer */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/muxtest" /* copybara-comment: muxtest */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */
)

var (
	endpoints = []string{
		// service info
		"GET /identity",

		// asset path
		"/identity/static/",

		// login related
		"GET /identity/login",
		"GET /identity/consent",
		"GET /identity/v1alpha/{realm}/login/{name}",
		"GET /identity/loggedin",
		"GET /identity/v1alpha/{realm}/loggedin/{name}",
		"POST /identity/inforelease/accept",
		"POST /identity/inforelease/reject",

		// jwks for IC signed visas
		"GET /visas/jwks",

		// proxy hydra token endpoint
		"POST /oauth2/token",

		// consent management endpoints
		"GET /identity/v1alpha/{realm}/users/{user}/consents",
		"DELETE /identity/v1alpha/{realm}/users/{user}/consents/{consent_id}",

		// token management endpoints
		"GET /identity/v1alpha/users/{user}/tokens",
		"DELETE /identity/v1alpha/users/{user}/tokens/{token_id}",

		// auditlogs related
		"GET /identity/v1alpha/users/{user}/auditlogs",

		// cli client related
		"/identity/cli/register/{name}",
		"GET /identity/cli/accept",
		"GET /identity/cli/auth/{name}",

		// scim related
		"/scim/v2/{realm}/Groups",
		"/scim/v2/{realm}/Groups/{name}",
		"/scim/v2/{realm}/Me",
		"/scim/v2/{realm}/Users",
		"/scim/v2/{realm}/Users/{name}",

		// administration endpoints
		"/identity/v1alpha/{realm}",
		"/identity/v1alpha/{realm}/admin/subjects/{name}/account/claims",
		"/identity/v1alpha/{realm}/admin/tokens",
		"/identity/v1alpha/{realm}/clients/{name}",
		"/identity/v1alpha/{realm}/clients:sync",
		"/identity/v1alpha/{realm}/config",
		"/identity/v1alpha/{realm}/config/clients/{name}",
		"/identity/v1alpha/{realm}/config/options",
		"GET /identity/v1alpha/{realm}/config/history",
		"GET /identity/v1alpha/{realm}/config/history/{name}",
		"GET /identity/v1alpha/{realm}/config/reset",

		// read-only non-admin access to configurations
		"/identity/v1alpha/{realm}/config/identityProviders/{name}",
		"GET /identity/v1alpha/{realm}/identityProviders",
		"GET /identity/v1alpha/{realm}/localeMetadata",
		"GET /identity/v1alpha/{realm}/passportTranslators",

		// fake endpoints, will remove soon
		"GET /tokens",
		"GET /tokens/",
		"DELETE /tokens/",
		"GET /consents",
		"DELETE /consents/",
	}
)

func TestEndpoints(t *testing.T) {
	r := mux.NewRouter()
	store := storage.NewMemoryStorage("ic-min", "testdata/config")
	proxy, err := hydraproxy.New(nil, "http://example.com", "http://example.com", store)
	if err != nil {
		t.Fatalf("hydraproxy.New() failed: %v", err)
	}

	server, err := fakeoidcissuer.New(hydraURL, &testkeys.PersonaBrokerKey, "dam-min", "testdata/config", false)
	if err != nil {
		t.Fatalf("fakeoidcissuer.New(%q, _, _) failed: %v", hydraURL, err)
	}

	New(r, &Options{
		HTTPClient:       server.Client(),
		Domain:           domain,
		AccountDomain:    domain,
		ServiceName:      "ic-min",
		Store:            store,
		UseHydra:         useHydra,
		HydraPublicURL:   hydraURL,
		HydraPublicProxy: proxy,
	})

	got := muxtest.PathsInRouter(t, r)
	want := stringset.New(endpoints...)

	if d := cmp.Diff(want, got); len(d) > 0 {
		t.Errorf("PathsInRouter() (-want, +got): %s", d)
	}
}
