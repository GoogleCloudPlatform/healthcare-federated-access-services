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

package ic

import (
	"net/http"
	"testing"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/kms/fakeencryption" /* copybara-comment: fakeencryption */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakeoidcissuer" /* copybara-comment: fakeoidcissuer */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test" /* copybara-comment: test */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */
)

func TestConfigHandlers(t *testing.T) {
	store := storage.NewMemoryStorage("ic-min", "testdata/config")
	server, err := fakeoidcissuer.New(hydraURL, &testkeys.PersonaBrokerKey, "dam-min", "testdata/config", false)
	if err != nil {
		t.Fatalf("fakeoidcissuer.New(%q, _, _) failed: %v", hydraURL, err)
	}
	crypt := fakeencryption.New()

	opts := &Options{
		HTTPClient:     server.Client(),
		Domain:         domain,
		ServiceName:    "ic",
		AccountDomain:  domain,
		Store:          store,
		Encryption:     crypt,
		UseHydra:       useHydra,
		HydraAdminURL:  hydraAdminURL,
		HydraPublicURL: hydraURL,
	}
	s := NewService(opts)

	tests := []test.HandlerTest{
		{
			Method: "GET",
			Path:   "/identity/v1alpha/test/identityProviders",
			Output: `{"identityProviders":{"idp":{"issuer":"https://hydra.example.com/","ui":{"description":"Example identity provider","iconUrl":"/identity/static/images/idp.png","label":"Example"}}}}`,
			Status: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/identity/v1alpha/test/passportTranslators",
			Output: `{"passportTranslators":{"dbgap_translator":{"compatibleIssuers":["https://dbgap.nlm.nih.gov/aa"],"ui":{"label":"dbGaP Passport Translator"}}}}`,
			Status: http.StatusOK,
		},
	}
	test.HandlerTests(t, s.Handler, tests, hydraURL, server.Config())
}
