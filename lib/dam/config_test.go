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

package dam

import (
	"net/http"
	"testing"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds" /* copybara-comment: clouds */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakeoidcissuer" /* copybara-comment: fakeoidcissuer */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test" /* copybara-comment: test */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */
)

func TestConfigHandlers(t *testing.T) {
	store := storage.NewMemoryStorage("dam", "testdata/config")
	wh := clouds.NewMockTokenCreator(false)
	server, err := fakeoidcissuer.New(hydraPublicURL, &testkeys.PersonaBrokerKey, "dam", "testdata/config", false)
	if err != nil {
		t.Fatalf("fakeoidcissuer.New(%q, _, _) failed: %v", hydraPublicURL, err)
	}

	s := NewService(&Options{
		HTTPClient:     server.Client(),
		Domain:         "test.org",
		ServiceName:    "dam",
		DefaultBroker:  "no-broker",
		Store:          store,
		Warehouse:      wh,
		UseHydra:       useHydra,
		HydraAdminURL:  hydraAdminURL,
		HydraPublicURL: hydraPublicURL,
	})

	role := `{"roleCategories":["metadata"],"policyBasis":{"AcceptedTermsAndPolicies":true,"ResearcherStatus":true}}`
	roles := `{"discovery":` + role + `}`
	beacon := `{"serviceTemplate":"beacon",*,"contentTypes":["application/bam"],"roles":` + roles + `,"ui":{"description":"Search data from Beacon Discovery","label":"Beacon Discovery"},"interfaces":{"http:beacon":{"uri":["https://gatekeeper-cafe-variome.staging.dnastack.com/beacon/query"]}}}`
	views := `{"beacon":` + beacon + `,"gcs_read":{"serviceTemplate":"gcs",*,"contentTypes":["application/bam"],"roles":{"viewer":{"roleCategories":["list","metadata","read"],"policyBasis":{"AcceptedTermsAndPolicies":true,"ResearcherStatus":true}}},"ui":{"description":"GCS File Read","label":"File Read"},"interfaces":{"gcp:gs":{"uri":["gs://ga4gh-apis-controlled-access"]},"http:gcp:gs":{"uri":["https://www.googleapis.com/storage/v1/b/ga4gh-apis-controlled-access"]}}}}`
	resource := `{"views":` + views + `,"maxTokenTtl":"1h","ui":{"applyUrl":"http://apply.ga4gh-apis.org","description":"Google demo of GA4GH APIs","imageUrl":"https://info.ga4gh-apis.org/images/image.jpg","infoUrl":"http://info.ga4gh-apis.org","label":"GA4GH APIs","troubleshootUrl":"http://troubleshoot.ga4gh-apis.org"}}`

	tests := []test.HandlerTest{
		{
			Method: "GET",
			Path:   "/dam/v1alpha/test/resources",
			Output: `*"ga4gh-apis":` + resource + "*",
			Status: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/dam/v1alpha/test/resources/ga4gh-apis",
			Output: `*{"resource":` + resource + `,"access":["ga4gh-apis/beacon/discovery","ga4gh-apis/gcs_read/viewer"]}*`,
			Status: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/dam/v1alpha/test/resources/ga4gh-apis/views",
			Output: `*{"views":` + views + `,"access":["ga4gh-apis/beacon/discovery","ga4gh-apis/gcs_read/viewer"]}*`,
			Status: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/dam/v1alpha/test/resources/ga4gh-apis/views/beacon",
			Output: `*{"view":` + beacon + `,"access":["ga4gh-apis/beacon/discovery"]}*`,
			Status: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/dam/v1alpha/test/resources/ga4gh-apis/views/beacon/roles",
			Output: `{"roles":` + roles + `,"access":["ga4gh-apis/beacon/discovery"]}`,
			Status: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/dam/v1alpha/test/resources/ga4gh-apis/views/beacon/roles/discovery",
			Output: `{"role":` + role + `,"access":["ga4gh-apis/beacon/discovery"]}`,
			Status: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/dam/v1alpha/test/flatViews",
			Output: `*"views":{"/dataset_example/bq_read/viewer/http:gcp:bq/text/csv":{"resourcePath":"/dam/v1alpha/test/resources/dataset_example/views/bq_read/roles/viewer","umbrella":"dataset_example","resourceName":"dataset_example","viewName":"bq_read","roleName":"viewer","interfaceName":"http:gcp:bq","interfaceUri":"https://www.googleapis.com/bigquery/v1/projects/dataset-example-project","contentType":"*","labels":{*},"serviceName":"bigquery","platform":"gcp","platformService":"bigquery","maxTokenTtl":"3h","resourceUi":{*},"viewUi":{*},"roleUi":{*},"roleCategories":["list","metadata","read"]*`,
			Status: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/dam/v1alpha/master/services",
			Output: `*"gcs":{"platform":"gcp","serviceVariables":{*},"itemVariables":{"bucket":*,"paths":*,"project":*,"type":*},"properties":{"canBeAggregated":true}*`,
			Status: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/dam/v1alpha/master/passportTranslators",
			Output: `{"passportTranslators":{"dbgap_translator":{"compatibleIssuers":["https://dbgap.nlm.nih.gov/aa"],"ui":{"label":"dbGaP Passport Translator"}},"elixir_translator":{"compatibleIssuers":["https://login.elixir-czech.org/oidc","https://login.elixir-czech.org/oidc/"],"ui":{"label":"Elixir Passport Translator"}}}}`,
			Status: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/dam/v1alpha/master/damRoleCategories",
			Output: `*"read":{"order":5,"ui":{*}}*`,
			Status: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/dam/v1alpha/master/testPersonas",
			Output: `^.*dr_joe.*standardClaims.*"iss":"Issuer of the Passport".*$`,
			Status: http.StatusOK,
		},
	}
	test.HandlerTests(t, s.Handler, tests, hydraPublicURL, server.Config())
}
