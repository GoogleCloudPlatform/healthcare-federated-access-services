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

package dam

import (
	"testing"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"github.com/gorilla/mux" /* copybara-comment */
	"bitbucket.org/creachadair/stringset" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/aws"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/hydraproxy" /* copybara-comment: hydraproxy */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakeoidcissuer" /* copybara-comment: fakeoidcissuer */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/muxtest" /* copybara-comment: muxtest */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */
)

var (
	endpoints = []string{
		// service info
		"GET /dam",

		// asset path
		"/dam/static/",

		// login related
		"GET /dam/login",
		"GET /dam/consent",
		"GET /dam/oidc/loggedin",
		"GET|POST /dam/checkout",

		// proxy hydra token endpoint
		"POST /oauth2/token",

		// OIDC well-known for gatekeeper tokens
		"GET /dam/gatekeeper/.well-known/jwks",
		"GET /dam/gatekeeper/.well-known/openid-configuration",

		// token management endpoints
		"GET /dam/v1alpha/users/{user}/tokens",
		"DELETE /dam/v1alpha/users/{user}/tokens/{token_id}",

		// auditlogs related
		"GET /dam/v1alpha/users/{user}/auditlogs",

		// administration endpoints
		"/dam/v1alpha/{realm}",
		"/dam/v1alpha/{realm}/clients:sync",
		"/dam/v1alpha/{realm}/config",
		"/dam/v1alpha/{realm}/config/clients/{name}",
		"/dam/v1alpha/{realm}/config/options",
		"/dam/v1alpha/{realm}/config/policies/{name}",
		"/dam/v1alpha/{realm}/config/resources/{name}",
		"/dam/v1alpha/{realm}/config/resources/{resource}/views/{name}",
		"/dam/v1alpha/{realm}/config/serviceTemplates/{name}",
		"/dam/v1alpha/{realm}/config/testPersonas/{name}",
		"/dam/v1alpha/{realm}/config/trustedIssuers/{name}",
		"/dam/v1alpha/{realm}/config/trustedSources/{name}",
		"/dam/v1alpha/{realm}/config/visaTypes/{name}",
		"GET /dam/v1alpha/{realm}/config/history",
		"GET /dam/v1alpha/{realm}/config/history/{name}",
		"GET /dam/v1alpha/{realm}/config/reset",
		"GET /dam/v1alpha/{realm}/config/testPersonas",

		// read-only non-admin access to configurations
		"/dam/v1alpha/{realm}/client/{name}",
		"GET /dam/v1alpha/{realm}/damRoleCategories",
		"GET /dam/v1alpha/{realm}/flatViews",
		"GET /dam/v1alpha/{realm}/passportTranslators",
		"GET /dam/v1alpha/{realm}/resources",
		"GET /dam/v1alpha/{realm}/resources/{name}",
		"GET /dam/v1alpha/{realm}/resources/{name}/views",
		"GET /dam/v1alpha/{realm}/resources/{name}/views/{view}",
		"GET /dam/v1alpha/{realm}/resources/{name}/views/{view}/roles",
		"GET /dam/v1alpha/{realm}/resources/{name}/views/{view}/roles/{role}",
		"GET /dam/v1alpha/{realm}/services",
		"GET /dam/v1alpha/{realm}/testPersonas",

		// processes: the state of various background processes running in DAM.
		"/dam/v1alpha/{realm}/processes",
		"/dam/v1alpha/{realm}/processes/{name}",

		// scim related
		"/identity/scim/v2/{realm}/Groups",
		"/identity/scim/v2/{realm}/Groups/{name}",
		"/identity/scim/v2/{realm}/Me",
		"/identity/scim/v2/{realm}/Users",
		"/identity/scim/v2/{realm}/Users/{name}",

		// fake endpoints, will remove soon
		"GET /tokens",
		"DELETE /tokens/",
		"GET /consents",
		"DELETE /consents/",
	}
)

func TestEndpoints(t *testing.T) {
	r := mux.NewRouter()
	store := storage.NewMemoryStorage("dam-min", "testdata/config")
	proxy, err := hydraproxy.New(nil, "http://example.com", "http://example.com", store)
	if err != nil {
		t.Fatalf("hydraproxy.New() failed: %v", err)
	}
	server, err := fakeoidcissuer.New(hydraPublicURL, &testkeys.PersonaBrokerKey, "dam", "testdata/config", false)
	if err != nil {
		t.Fatalf("fakeoidcissuer.New(%q, _, _) failed: %v", hydraPublicURL, err)
	}
	awsClient := aws.NewMockAPIClient("123456", "dam-user-id")

	New(r, &Options{
		HTTPClient:       server.Client(),
		Domain:           "test.org",
		ServiceName:      "dam",
		Store:            store,
		AWSClient:        awsClient,
		UseHydra:         useHydra,
		HydraPublicProxy: proxy,
		HydraPublicURL:   hydraPublicURL,
	})

	got := muxtest.PathsInRouter(t, r)
	want := stringset.New(endpoints...)

	if d := cmp.Diff(want, got); len(d) > 0 {
		t.Errorf("PathsInRouter() (-want, +got): %s", d)
	}
}
