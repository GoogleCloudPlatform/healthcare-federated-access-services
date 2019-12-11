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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"github.com/google/go-cmp/cmp/cmpopts" /* copybara-comment */
	"github.com/gorilla/mux" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/apis/hydraapi" /* copybara-comment: hydraapi */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds" /* copybara-comment: clouds */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/hydra" /* copybara-comment: hydra */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/persona" /* copybara-comment: persona */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakehydra" /* copybara-comment: fakehydra */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakeoidcissuer" /* copybara-comment: fakeoidcissuer */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/httptestclient" /* copybara-comment: httptestclient */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test" /* copybara-comment: test */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
)

const (
	damURL           = "https://dam.example.com"
	hydraAdminURL    = "https://admin.hydra.example.com"
	hydraURL         = "https://example.com/oidc"
	testBroker       = "testBroker"
	notUseHydra      = false
	useHydra         = true
	loginChallenge   = "lc-1234"
	loginStateID     = "ls-1234"
	consentChallenge = "cc-1234"
	consentStateID   = "cs-1234"
)

// transformJSON is a cmp.Option that transform strings into structured objects
// for properly comparing JSON in a way that is agnostic towards the trivial
// changes in the output.
var transformJSON = cmpopts.AcyclicTransformer("ParseJSON", func(in string) (out interface{}) {
	if err := json.Unmarshal([]byte(in), &out); err != nil {
		return in
	}
	return out
})

func TestHandlers(t *testing.T) {
	store := storage.NewMemoryStorage("dam", "testdata/config")
	wh := clouds.NewMockTokenCreator(false)
	server, err := fakeoidcissuer.New(test.TestIssuerURL, &testkeys.PersonaBrokerKey, "dam", "testdata/config")
	if err != nil {
		t.Fatalf("fakeoidcissuer.New(%q, _, _) failed: %v", test.TestIssuerURL, err)
	}
	ctx := server.ContextWithClient(context.Background())
	s := NewService(ctx, "test.org", "no-broker", hydraAdminURL, store, wh, notUseHydra)
	tests := []test.HandlerTest{
		{
			Method: "GET",
			Path:   "/dam",
			Output: `{"name":"Data Access Manager","versions":["v1alpha"],"ui":{"description":"Test DAM","label":"Test DAM"}}`,
			CmpOptions: cmp.Options{transformJSON, cmpopts.IgnoreMapEntries(func(k string, v interface{}) bool {
				return k == "startTime"
			})},
			Status: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/dam/v1alpha/master/targetAdapters",
			Output: `^.+$`,
			Status: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/dam/v1alpha/master/passportTranslators",
			Output: `^.+$`,
			Status: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/dam/v1alpha/master/damRoleCategories",
			Output: `^.+$`,
			Status: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/dam/v1alpha/master/testPersonas",
			Output: `^.*dr_joe.*standardClaims.*"iss":"Issuer of the Passport".*$`,
			Status: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/dam/v1alpha/master",
			Output: `{}`,
			Status: http.StatusOK,
		},
		{
			Method: "POST",
			Path:   "/dam/v1alpha/test",
			Output: `^.*exists`,
			// For now, all realms are marked as already in existence.
			Status: http.StatusConflict,
		},
		{
			Method: "PUT",
			Path:   "/dam/v1alpha/test",
			Output: ``,
			Status: http.StatusOK,
		},
		{
			Method: "PATCH",
			Path:   "/dam/v1alpha/test",
			Output: ``,
			Status: http.StatusOK,
		},
		{
			Method: "DELETE",
			Path:   "/dam/v1alpha/test",
			Output: ``,
			Status: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/dam/v1alpha/master/processes",
			Output: `^\{"processes":\{.*"gckeys"`,
			Status: http.StatusOK,
		},
		{
			Method: "POST",
			Path:   "/dam/v1alpha/master/processes",
			Output: `^.*exists`,
			Status: http.StatusConflict,
		},
		{
			Method: "PUT",
			Path:   "/dam/v1alpha/master/processes",
			Output: `^.*not allowed`,
			Status: http.StatusBadRequest,
		},
		{
			Method: "PATCH",
			Path:   "/dam/v1alpha/master/processes",
			Output: `^.*not allowed`,
			Status: http.StatusBadRequest,
		},
		{
			Method: "DELETE",
			Path:   "/dam/v1alpha/master/processes",
			Output: `^.*not allowed`,
			Status: http.StatusBadRequest,
		},
		{
			Method: "GET",
			Path:   "/dam/v1alpha/master/processes/gckeys",
			Output: `^\{"process":\{.*"processName":"gckeys"`,
			Status: http.StatusOK,
		},
		{
			Method: "POST",
			Path:   "/dam/v1alpha/master/processes/gckeys",
			Output: `^.*exists`,
			Status: http.StatusConflict,
		},
		{
			Method: "PUT",
			Path:   "/dam/v1alpha/master/processes/gckeys",
			Output: `^.*not allowed`,
			Status: http.StatusBadRequest,
		},
		{
			Method: "PATCH",
			Path:   "/dam/v1alpha/master/processes/gckeys",
			Output: `^.*not allowed`,
			Status: http.StatusBadRequest,
		},
		{
			Method: "DELETE",
			Path:   "/dam/v1alpha/master/processes/gckeys",
			Output: `^.*not allowed`,
			Status: http.StatusBadRequest,
		},
		{
			Method: "GET",
			Path:   "/dam/v1alpha/master/config",
			Output: `^.*dr_joe.*$`,
			Status: http.StatusOK,
		},
		{
			Method: "POST",
			Path:   "/dam/v1alpha/master/config",
			Input:  `{}`,
			Output: `^.*exists`,
			Status: http.StatusConflict,
		},
		{
			Method: "PUT",
			Path:   "/dam/v1alpha/master/config",
			Input:  `{"item":{"version":"v100"}}`,
			Output: `^.*version`,
			Status: http.StatusBadRequest,
		},
		{
			Method: "PUT",
			Path:   "/dam/v1alpha/test/config",
			Input:  `{"item": $(GET /dam/v1alpha/master/config)}`,
			Output: ``,
			Status: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/dam/v1alpha/test/config/options",
			Output: `^.*readOnlyMasterRealm.*"descriptors".*readOnlyMasterRealm`,
			Status: http.StatusOK,
		},
		{
			Method: "POST",
			Path:   "/dam/v1alpha/test/config/options",
			Input:  `{}`,
			Output: `^.*exists`,
			Status: http.StatusConflict,
		},
		{
			Method: "PUT",
			Path:   "/dam/v1alpha/test/config/options",
			Input:  `{"item": $(GET /dam/v1alpha/test/config/options)}`,
			Status: http.StatusOK,
		},
		{
			Method: "PATCH",
			Path:   "/dam/v1alpha/test/config/options",
			Input:  `{"item": {"gcpServiceAccountProject": "patch-options-project"}}`,
			Status: http.StatusOK,
		},
		{
			Method: "DELETE",
			Path:   "/dam/v1alpha/test/config/options",
			Output: `^.*DELETE not allowed`,
			Status: http.StatusBadRequest,
		},
		{
			Method: "GET",
			Path:   "/dam/v1alpha/test/config/resources/ga4gh-apis",
			Output: `^.*"views"`,
			Status: http.StatusOK,
		},
		{
			Method: "POST",
			Path:   "/dam/v1alpha/test/config/resources/new-resource",
			Input:  `{"item":{"maxTokenTtl": "3h","ui":{"label":"label","description":"desc"}}}`,
			Output: ``,
			Status: http.StatusOK,
		},
		{
			Name:   "PUT /dam/v1alpha/test/config/resources/new-resource (unordered access list)",
			Method: "PUT",
			Path:   "/dam/v1alpha/test/config/resources/new-resource",
			Input:  `{"item": $(GET /dam/v1alpha/test/config/resources/ga4gh-apis), "modification": {"testPersonas":{"dr_joe_elixir":{"access":["ga4gh-apis/gcs_read/viewer","ga4gh-apis/beacon/discovery","new-resource/beacon/discovery","new-resource/gcs_read/viewer"]}}}}`,
			Status: http.StatusOK,
		},
		{
			Method: "PATCH",
			Path:   "/dam/v1alpha/test/config/resources/new-resource",
			Input:  `{"item": {"ui":{"label":"foo","description":"bar"}}, "modification": {"testPersonas":{"dr_joe_elixir":{"access":["ga4gh-apis/beacon/discovery","ga4gh-apis/gcs_read/viewer"]}}}}`,
			Status: http.StatusOK,
		},
		{
			Method: "DELETE",
			Path:   "/dam/v1alpha/test/config/resources/new-resource",
			Output: ``,
			Status: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/dam/v1alpha/test/config/resources/ga4gh-apis/views/gcs_read",
			Output: `^.*"serviceTemplate"`,
			Status: http.StatusOK,
		},
		{
			Method: "POST",
			Path:   "/dam/v1alpha/test/config/resources/ga4gh-apis/views/gcs_read2",
			Input:  `{"item":$(GET /dam/v1alpha/test/config/resources/ga4gh-apis/views/gcs_read), "modification": {"testPersonas":{"dr_joe_elixir":{"access":["ga4gh-apis/beacon/discovery","ga4gh-apis/gcs_read/viewer","ga4gh-apis/gcs_read2/viewer"]}}}}`,
			Output: ``,
			Status: http.StatusOK,
		},
		{
			Method: "PUT",
			Path:   "/dam/v1alpha/test/config/resources/ga4gh-apis/views/gcs_read2",
			Input: `{
									"item": {
										"serviceTemplate":"gcs",
										"version":"Phase 3",
										"items": [
											{
												"vars": {
													"project": "ga4gh-apis",
													"bad-var-name": "ga4gh-apis-controlled-access"
												}
											}
										],
										"roles":{
											"viewer":{
												"policies":[
													{"name":"bona_fide"}, {"name":"ethics"}
												]
											}
										},
					          "defaultRole": "viewer",
										"ui": {
											"label": "foo",
											"description": "bar"
										}
									},
									"modification": {
									}
								}`,
			Output: `{"code":3,"message":"access requirements: target adapter \"token:gcp:sa\" item format \"gcs\" variable \"bad-var-name\" is undefined","details":[{"@type":"type.googleapis.com/google.rpc.ResourceInfo","resourceName":"resources/ga4gh-apis/views/gcs_read2/items/0/vars/bad-var-name","description":"access requirements: target adapter \"token:gcp:sa\" item format \"gcs\" variable \"bad-var-name\" is undefined"}]}`,
			Status: http.StatusBadRequest,
		},
		{
			Method: "PUT",
			Path:   "/dam/v1alpha/test/config/resources/ga4gh-apis/views/gcs_read2",
			Input: `{
									"item": {
										"serviceTemplate":"gcs",
										"version":"Phase 3",
										"items": [
											{
												"vars": {
													"project": "ga4gh-apis",
													"bucket": "ga4gh-apis-controlled-access"
												}
											}
										],
										"roles":{
											"viewer":{
												"policies":[
													{"name":"bona_fide"}, {"name":"ethics"}
												]
											}
										},
					          "defaultRole": "viewer",
										"ui": {
											"label": "foo",
											"description": "bar"
										}
									},
									"modification": {
									}
								}`,
			Status: http.StatusOK,
		},
		{
			Method: "PATCH",
			Path:   "/dam/v1alpha/test/config/resources/ga4gh-apis/views/gcs_read2",
			Input: `{
									"item": {
										"items": [
											{
												"vars": {
													"project": "ga4gh-apis",
													"bucket": "ga4gh-apis-controlled-access"
												}
											}
										],
										"roles":{
											"viewer":{
												"policies":[
													{"name":"bona_fide"}, {"name":"ethics"}
												]
											}
										},
										"ui": {
											"label": "foo",
											"description": "bar"
										}
									},
									"modification": {
									}
								}`,
			Status: http.StatusOK,
		},
		{
			Method: "DELETE",
			Path:   "/dam/v1alpha/test/config/resources/ga4gh-apis/views/gcs_read2",
			Output: ``,
			Status: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/dam/v1alpha/test/config/trustedPassportIssuers/elixir",
			Output: `^.*"issuer"`,
			Status: http.StatusOK,
		},
		{
			Method: "POST",
			Path:   "/dam/v1alpha/test/config/trustedPassportIssuers/new-issuer",
			Input:  `{"item":{"issuer":"https://test.org","ui":{"label":"foo","description":"bar"}}}`,
			Output: ``,
			Status: http.StatusOK,
		},
		{
			Method: "PUT",
			Path:   "/dam/v1alpha/test/config/trustedPassportIssuers/new-issuer",
			Input:  `{"item":{"issuer":"https://test.org","ui":{"label":"foo","description":"bar"}}}`,
			Status: http.StatusOK,
		},
		{
			Method: "PATCH",
			Path:   "/dam/v1alpha/test/config/trustedPassportIssuers/new-issuer",
			Input:  `{"item":{"issuer":"https://test2.org","ui":{"label":"foo","description":"bar"}}}`,
			Status: http.StatusOK,
		},
		{
			Method: "DELETE",
			Path:   "/dam/v1alpha/test/config/trustedPassportIssuers/new-issuer",
			Output: ``,
			Status: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/dam/v1alpha/test/config/trustedSources/elixir_institutes",
			Output: `^.*"sources"`,
			Status: http.StatusOK,
		},
		{
			Method: "POST",
			Path:   "/dam/v1alpha/test/config/trustedSources/new-source",
			Input:  `{"item":{"sources":["https://test.org"],"ui":{"label":"foo","description":"bar"}}}`,
			Output: ``,
			Status: http.StatusOK,
		},
		{
			Method: "PUT",
			Path:   "/dam/v1alpha/test/config/trustedSources/new-source",
			Input:  `{"item":{"sources":["https://test2.org"],"ui":{"label":"foo","description":"bar"}}}`,
			Status: http.StatusOK,
		},
		{
			Method: "PATCH",
			Path:   "/dam/v1alpha/test/config/trustedSources/new-source",
			Input:  `{"item":{"sources":["https://test3.org"],"ui":{"label":"foo","description":"bar"}}}`,
			Status: http.StatusOK,
		},
		{
			Method: "DELETE",
			Path:   "/dam/v1alpha/test/config/trustedSources/new-source",
			Output: ``,
			Status: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/dam/v1alpha/test/config/policies/bona_fide",
			Output: `^.*"anyOf"`,
			Status: http.StatusOK,
		},
		{
			Method: "POST",
			Path:   "/dam/v1alpha/test/config/policies/new-policy",
			Input:  `{"item":{"anyOf":[{"allOf":[{"type":"BonaFide","value":"const:https://test.org"}]}],"ui":{"label":"foo","description":"bar"}}}`,
			Output: ``,
			Status: http.StatusOK,
		},
		{
			Method: "PUT",
			Path:   "/dam/v1alpha/test/config/policies/new-policy",
			Input:  `{"item":{"anyOf":[{"allOf":[{"type":"BonaFide","value":"const:https://test2.org"}]}],"ui":{"label":"foo","description":"bar"}}}`,
			Status: http.StatusOK,
		},
		{
			Method: "PATCH",
			Path:   "/dam/v1alpha/test/config/policies/new-policy",
			Input:  `{"item":{"anyOf":[{"allOf":[{"type":"BonaFide","value":"const:https://test3.org"}]}],"ui":{"label":"foo","description":"bar"}}}`,
			Status: http.StatusOK,
		},
		{
			Method: "DELETE",
			Path:   "/dam/v1alpha/test/config/policies/new-policy",
			Output: ``,
			Status: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/dam/v1alpha/test/config/claimDefinitions/BonaFide",
			Output: `^.*"ui"`,
			Status: http.StatusOK,
		},
		{
			Method: "POST",
			Path:   "/dam/v1alpha/test/config/claimDefinitions/new.claim",
			Input:  `{"item":{"ui":{"label":"new.Claim","description":"bar"}}}`,
			Output: ``,
			Status: http.StatusOK,
		},
		{
			Method: "PUT",
			Path:   "/dam/v1alpha/test/config/claimDefinitions/new.claim",
			Input:  `{"item":{"ui":{"label":"new.Claim2","description":"bar"}}}`,
			Status: http.StatusOK,
		},
		{
			Method: "PATCH",
			Path:   "/dam/v1alpha/test/config/claimDefinitions/new.claim",
			Input:  `{"item":{"ui":{"label":"new.Claim3","description":"bar"}}}`,
			Status: http.StatusOK,
		},
		{
			Method: "DELETE",
			Path:   "/dam/v1alpha/test/config/claimDefinitions/new.claim",
			Output: ``,
			Status: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/dam/v1alpha/test/config/serviceTemplates/gcs",
			Output: `^.*"targetAdapter"`,
			Status: http.StatusOK,
		},
		{
			Method: "POST",
			Path:   "/dam/v1alpha/test/config/serviceTemplates/new-service",
			Input:  `{"item":$(GET /dam/v1alpha/test/config/serviceTemplates/gcs)}`,
			Output: ``,
			Status: http.StatusOK,
		},
		{
			Method: "PUT",
			Path:   "/dam/v1alpha/test/config/serviceTemplates/new-service",
			Input:  `{"item":$(GET /dam/v1alpha/test/config/serviceTemplates/gcs)}`,
			Status: http.StatusOK,
		},
		{
			Method: "PATCH",
			Path:   "/dam/v1alpha/test/config/serviceTemplates/new-service",
			Input:  `{"item":{"interfaces":{"gcp:gs":"gs://${bucket}"},"ui":{"label":"foo","description":"bar"}}}`,
			Status: http.StatusOK,
		},
		{
			Method: "DELETE",
			Path:   "/dam/v1alpha/test/config/serviceTemplates/new-service",
			Output: ``,
			Status: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/dam/v1alpha/test/config/testPersonas/dr_joe_elixir",
			Output: `^.*"passport"`,
			Status: http.StatusOK,
		},
		{
			Method: "POST",
			Path:   "/dam/v1alpha/test/config/testPersonas/new-persona",
			Input:  `{"item":$(GET /dam/v1alpha/test/config/testPersonas/dr_joe_elixir)}`,
			Output: ``,
			Status: http.StatusOK,
		},
		{
			Method: "PUT",
			Path:   "/dam/v1alpha/test/config/testPersonas/new-persona",
			Input:  `{"item":$(GET /dam/v1alpha/test/config/testPersonas/dr_joe_elixir)}`,
			Status: http.StatusOK,
		},
		{
			Method: "PATCH",
			Path:   "/dam/v1alpha/test/config/testPersonas/new-persona",
			Input:  `{"item":$(GET /dam/v1alpha/test/config/testPersonas/dr_joe_elixir)}`,
			Status: http.StatusOK,
		},
		{
			Method: "DELETE",
			Path:   "/dam/v1alpha/test/config/testPersonas/new-persona",
			Output: ``,
			Status: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/dam/v1alpha/test/config/clients/test_client",
			Output: `^.*"clientId"`,
			Status: http.StatusOK,
		},
		{
			Method: "POST",
			Path:   "/dam/v1alpha/test/config/clients/new-client",
			Input:  `{"item":{"ui":{"label":"new-client","description":"bar"}}}`,
			Output: ``,
			Status: http.StatusOK,
		},
		{
			Method: "PUT",
			Path:   "/dam/v1alpha/test/config/clients/new-client",
			Input:  `{"item":{"ui":{"label":"new-client2","description":"bar"}}}`,
			Status: http.StatusOK,
		},
		{
			Method: "PATCH",
			Path:   "/dam/v1alpha/test/config/clients/new-client",
			Input:  `{"item":{"ui":{"label":"new-client3","description":"bar"}}}`,
			Status: http.StatusOK,
		},
		{
			Method: "DELETE",
			Path:   "/dam/v1alpha/test/config/clients/new-client",
			Output: ``,
			Status: http.StatusOK,
		},
		{
			Name:   "Claim condition dependency check (student vs. faculty)",
			Method: "PATCH",
			Path:   "/dam/v1alpha/test/config/testPersonas/dr_joe_era_commons",
			Input: `{"item":
				{
					"ui": {
						"label": "dr_joe_era_commons test"
					},
					"passport": {
						"standardClaims": {
							"iss": "https://login.nih.gov/oidc/",
							"sub": "dr_joe@era.nih.gov",
							"picture": "https://pbs.twimg.com/profile_images/3443048571/ef5062acfce64a7aef1d75b4934fbee6_400x400.png"
						},
						"ga4ghAssertions": [
							{
								"type": "AffiliationAndRole",
								"source": "https://example.edu",
								"value": "student@example.edu",
								"assertedDuration": "1d",
								"expiresDuration": "30d",
								"by": "so"
							},
							{
								"type": "ControlledAccessGrants",
								"source": "https://dbgap.nlm.nih.gov/aa",
								"value": "https://dac.nih.gov/datasets/phs000710",
								"assertedDuration": "1d",
								"expiresDuration": "30d",
								"by": "dac",
								"anyOfConditions": [
       		      	{
                		"allOf": [
                  		{
                    		"type": "AffiliationAndRole",
                    		"value": "const:faculty@example.edu",
                    		"by": "const:so"
                  		}
                		]
              		}
            		]
							}
						]
					},
					"access": [
						"dataset_example/bq_read/viewer",
						"dataset_example/gcs_read/viewer",
						"thousand-genomes/gcs-file-access/viewer"
					]
				}
			}`,
			Output: `^.*"removeAccess":\["dataset_example/`,
			Status: http.StatusBadRequest,
		},
		{
			Name:   "Claim condition dependency expired",
			Method: "PATCH",
			Path:   "/dam/v1alpha/test/config/testPersonas/dr_joe_era_commons",
			Input: `{"item":
				{
					"ui": {
						"label": "dr_joe_era_commons test"
					},
					"passport": {
						"standardClaims": {
							"iss": "https://login.nih.gov/oidc/",
							"sub": "dr_joe@era.nih.gov",
							"picture": "https://pbs.twimg.com/profile_images/3443048571/ef5062acfce64a7aef1d75b4934fbee6_400x400.png"
						},
						"ga4ghAssertions": [
							{
								"type": "AffiliationAndRole",
								"source": "https://example.edu",
								"value": "faculty@example.edu",
								"assertedDuration": "30d",
								"expiresDuration": "-1d",
								"by": "so"
							},
							{
								"type": "ControlledAccessGrants",
								"source": "https://dbgap.nlm.nih.gov/aa",
								"value": "https://dac.nih.gov/datasets/phs000710",
								"assertedDuration": "1d",
								"expiresDuration": "30d",
								"by": "dac",
								"anyOfConditions": [
       		      	{
                		"allOf": [
                  		{
                    		"type": "AffiliationAndRole",
                    		"value": "const:faculty@example.edu",
                    		"by": "const:so"
                  		}
                		]
              		}
            		]
							}
						]
					},
					"access": [
					  "dataset_example/bq_read/viewer",
						"dataset_example/gcs_read/viewer",
						"thousand-genomes/gcs-file-access/viewer"
					]
				}
			}`,
			Output: `^.*"removeAccess":\["dataset_example/`,
			Status: http.StatusBadRequest,
		},
		{
			Name:   "BonaFide claim expiry check",
			Method: "POST",
			Path:   "/dam/v1alpha/test/config/testPersonas/expired-persona",
			Input: `{"item":
				{
					"ui": {
						"label": "Dr. Joe (Elixir)"
					},
					"passport": {
						"standardClaims": {
							"iss": "https://login.elixir-czech.org/oidc/",
							"sub": "dr_joe@faculty.example.edu",
							"picture": "https://pbs.twimg.com/profile_images/497015367391121408/_cWXo-vA_400x400.jpeg"
						},
						"ga4ghAssertions": [
							{
								"type": "BonaFide",
								"source": "https://example.edu",
								"value": "https://www.nature.com/articles/s41431-018-0219-y",
								"assertedDuration": "1d",
								"expiresDuration": "30d",
								"by": "peer"
							},
							{
								"type": "AcceptedTermsAndPolicies",
								"source": "https://example.edu",
								"value": "https://www.nature.com/articles/s41431-018-0219-y",
								"assertedDuration": "1d",
								"expiresDuration": "30d",
								"by": "self"
							}
						]
					},
					"access" : [
						"ga4gh-apis/beacon/discovery",
						"ga4gh-apis/gcs_read/viewer"
					]
				}
			},`,
			Output: `^.*"removeAccess":\["ga4gh-apis/`,
			Status: http.StatusBadRequest,
		},
		{
			Method: "GET",
			Path:   "/dam/v1alpha/test/resources/ga4gh-apis/views/gcs_read/roles/viewer/token",
			Output: `^{.*"token":.*}`,
			Status: http.StatusOK,
		},
		{
			Method: "POST",
			Path:   "/dam/v1alpha/test/resources/ga4gh-apis/views/gcs_read/roles/viewer/token",
			Output: `^{.*"token":.*}`,
			Status: http.StatusOK,
		},
		{
			Method: "PUT",
			Path:   "/dam/v1alpha/test/resources/ga4gh-apis/views/gcs_read/roles/viewer/token",
			Output: `^.*not allowed`,
			Status: http.StatusBadRequest,
		},
		{
			Method: "PATCH",
			Path:   "/dam/v1alpha/test/resources/ga4gh-apis/views/gcs_read/roles/viewer/token",
			Output: `^.*not allowed`,
			Status: http.StatusBadRequest,
		},
		{
			Method: "DELETE",
			Path:   "/dam/v1alpha/test/resources/ga4gh-apis/views/gcs_read/roles/viewer/token",
			Output: "^.*not allowed",
			Status: http.StatusBadRequest,
		},
		{
			Method: "GET",
			Path:   "/dam/v1alpha/test/tokens",
			Output: `^\{"tokens":\[\{"name":.*\]}`,
			Status: http.StatusOK,
		},
		{
			Method: "POST",
			Path:   "/dam/v1alpha/test/tokens",
			Output: `^.*exists`,
			Status: http.StatusConflict,
		},
		{
			Method: "PUT",
			Path:   "/dam/v1alpha/test/tokens",
			Output: `^.*not allowed`,
			Status: http.StatusBadRequest,
		},
		{
			Method: "PATCH",
			Path:   "/dam/v1alpha/test/tokens",
			Output: `^.*not allowed`,
			Status: http.StatusBadRequest,
		},
		{
			Method: "DELETE",
			Path:   "/dam/v1alpha/test/tokens",
			Output: "",
			Status: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/dam/v1alpha/test/tokens",
			Output: `{}`,
			Status: http.StatusOK,
		},
		{
			Name:   "Add another service key for use with tests that follow",
			Method: "GET",
			Path:   "/dam/v1alpha/test/resources/ga4gh-apis/views/gcs_read/roles/viewer/token",
			Output: `^{.*"token":.*}`,
			Status: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/dam/v1alpha/test/tokens/none",
			Output: `^.*not found`,
			Status: http.StatusNotFound,
		},
		{
			Method: "GET",
			Path:   "/dam/v1alpha/test/tokens/3",
			Output: `^\{"token":\{"name":.*}`,
			Status: http.StatusOK,
		},
		{
			Method: "POST",
			Path:   "/dam/v1alpha/test/tokens/4",
			Output: `^.*not allowed`,
			Status: http.StatusBadRequest,
		},
		{
			Method: "PUT",
			Path:   "/dam/v1alpha/test/tokens/3",
			Output: `^.*not allowed`,
			Status: http.StatusBadRequest,
		},
		{
			Method: "PATCH",
			Path:   "/dam/v1alpha/test/tokens/3",
			Output: `^.*not allowed`,
			Status: http.StatusBadRequest,
		},
		{
			Method: "DELETE",
			Path:   "/dam/v1alpha/test/tokens/3",
			Output: "",
			Status: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/dam/v1alpha/test/tokens/3",
			Output: `^.*not found`,
			Status: http.StatusNotFound,
		},
	}
	test.HandlerTests(t, s.Handler, tests, test.TestIssuerURL, server.Config())
}

func TestMinConfig(t *testing.T) {
	store := storage.NewMemoryStorage("dam-min", "testdata/config")
	server, err := fakeoidcissuer.New(test.TestIssuerURL, &testkeys.PersonaBrokerKey, "dam-min", "testdata/config")
	if err != nil {
		t.Fatalf("fakeoidcissuer.New(%q, _, _) failed: %v", test.TestIssuerURL, err)
	}
	ctx := server.ContextWithClient(context.Background())
	s := NewService(ctx, "test.org", "no-broker", hydraAdminURL, store, nil, notUseHydra)
	tests := []test.HandlerTest{
		{
			Name:    "restricted access of 'dr_joe_elixir' (which only exists in min config subdirectory)",
			Method:  "GET",
			Path:    "/dam/v1alpha/test/config/testPersonas/dr_joe_elixir",
			Persona: "admin",
			Output:  `^.*"passport"`,
			Status:  http.StatusOK,
		},
		{
			Name:    "bad persona name",
			Method:  "GET",
			Path:    "/dam/v1alpha/test/config/testPersonas/min_joes",
			Persona: "admin",
			Output:  `^.*not found`,
			Status:  http.StatusNotFound,
		},
	}
	test.HandlerTests(t, s.Handler, tests, test.TestIssuerURL, server.Config())
}

type contextMatcher struct{}

func (contextMatcher) Matches(x interface{}) bool {
	c, ok := x.(context.Context)
	if !ok {
		return false
	}
	requestTTLInNanoFloat64 := "requested_ttl"
	_, ok = c.Value(requestTTLInNanoFloat64).(float64)
	if !ok {
		return false
	}
	return true
}

func (contextMatcher) String() string {
	return "context has requested_ttl"
}

func TestCheckAuthorization(t *testing.T) {
	store := storage.NewMemoryStorage("dam", "testdata/config")
	server, err := fakeoidcissuer.New(test.TestIssuerURL, &testkeys.PersonaBrokerKey, "dam", "testdata/config")
	if err != nil {
		t.Fatalf("fakeoidcissuer.New(%q, _, _) failed: %v", test.TestIssuerURL, err)
	}
	ctx := server.ContextWithClient(context.Background())
	s := NewService(ctx, "test.org", "no-broker", hydraAdminURL, store, nil, notUseHydra)

	realm := "master"
	cfg, err := s.loadConfig(nil, realm)
	if err != nil {
		t.Fatalf("cannot load config, %v", err)
	}

	pname := "dr_joe_elixir"
	p := cfg.TestPersonas[pname]
	acTok, _, err := persona.NewAccessToken(pname, test.TestIssuerURL, test.TestClientID, persona.DefaultScope, p)
	if err != nil {
		t.Fatalf("persona.NewAccessToken(%q, %q, _, _) failed: %v", pname, test.TestIssuerURL, err)
	}

	// Ensure pass context with TTL in validator
	var input io.Reader
	r := httptest.NewRequest("GET", "/dam/v1alpha/master/resources/ga4gh-apis/views/gcs_read/roles/viewer/token?client_id="+test.TestClientID+"&client_secret="+test.TestClientSecret, input)
	r.Header.Set("Authorization", "Bearer "+string(acTok))

	resName := "ga4gh-apis"
	viewName := "gcs_read"
	role := "viewer"
	ttl := time.Hour

	id, _, err := s.getPassportIdentity(cfg, nil, r)
	if err != nil {
		t.Fatalf("unable to obtain passport identity: %v", err)
	}

	status, err := s.checkAuthorization(id, ttl, resName, viewName, role, cfg, getClientID(r))
	if status != http.StatusOK || err != nil {
		t.Errorf("checkAuthorization(id, %v, %q, %q, %q, cfg, %q) failed, expected %q, got %q: %v", ttl, resName, viewName, role, getClientID(r), http.StatusOK, status, err)
	}

	// TODO: we need more tests for other condition in checkAuthorization()
}

func setupHydraTest() (*Service, *pb.DamConfig, *fakehydra.Server, error) {
	store := storage.NewMemoryStorage("dam", "testdata/config")
	server, err := fakeoidcissuer.New(hydraURL, &testkeys.PersonaBrokerKey, "dam", "testdata/config")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("fakeoidcissuer.New(%q, _, _) failed: %v", test.TestIssuerURL, err)
	}
	ctx := server.ContextWithClient(context.Background())
	wh := clouds.NewMockTokenCreator(false)
	s := NewService(ctx, "https://test.org", testBroker, hydraAdminURL, store, wh, useHydra)

	cfg, err := s.loadConfig(nil, storage.DefaultRealm)
	if err != nil {
		return nil, nil, nil, err
	}

	r := mux.NewRouter()
	h := fakehydra.New(r)
	s.httpClient = httptestclient.New(r)

	return s, cfg, h, nil
}

func sendLogin(s *Service, cfg *pb.DamConfig, h *fakehydra.Server, authParams string) *http.Response {
	h.GetLoginRequestResp = &hydraapi.LoginRequest{
		Challenge:  loginChallenge,
		RequestURL: hydraURL + "/oauth2/auth?" + authParams,
	}

	w := httptest.NewRecorder()
	params := fmt.Sprintf("?login_challenge=%s", loginChallenge)
	u := damURL + hydraLoginPath + params
	r := httptest.NewRequest(http.MethodGet, u, nil)

	s.Handler.ServeHTTP(w, r)

	resp := w.Result()

	return resp
}

func TestLogin_Hydra_Success(t *testing.T) {
	s, cfg, h, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	ga4ghGCS := url.QueryEscape("https://test.org/dam/master/resources/ga4gh-apis/views/gcs_read")
	ga4ghGCSViewer := url.QueryEscape("https://test.org/dam/master/resources/ga4gh-apis/views/gcs_read/roles/viewer")
	ga4ghBeaconDiscovery := url.QueryEscape("https://test.org/dam/master/resources/ga4gh-apis/views/beacon/roles/discovery")

	tests := []struct {
		name              string
		authParams        string
		wantTTL           int64
		wantResourceCount int
	}{
		{
			name:              "single resource with role",
			authParams:        "max_age=10&resource=" + ga4ghGCSViewer,
			wantTTL:           int64(10 * time.Second),
			wantResourceCount: 1,
		},
		{
			name:              "single resource without role",
			authParams:        "max_age=10&resource=" + ga4ghGCS,
			wantTTL:           int64(10 * time.Second),
			wantResourceCount: 1,
		},
		{
			name:              "multi resources",
			authParams:        "max_age=10&resource=" + ga4ghGCSViewer + "&resource=" + ga4ghBeaconDiscovery,
			wantTTL:           int64(10 * time.Second),
			wantResourceCount: 2,
		},
		{
			// TODO should remove ttl support.
			name:              "use ttl",
			authParams:        "ttl=1h&resource=" + ga4ghGCSViewer,
			wantTTL:           int64(time.Hour),
			wantResourceCount: 1,
		},
		{
			name:              "no ttl or maxAge",
			authParams:        "resource=" + ga4ghGCSViewer,
			wantTTL:           int64(defaultTTL),
			wantResourceCount: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := sendLogin(s, cfg, h, tc.authParams)
			if resp.StatusCode != http.StatusTemporaryRedirect {
				t.Errorf("resp.StatusCode wants %d, got %d", http.StatusTemporaryRedirect, resp.StatusCode)
			}

			idpc := cfg.TrustedPassportIssuers[s.defaultBroker]

			l := resp.Header.Get("Location")
			loc, err := url.Parse(l)
			if err != nil {
				t.Fatalf("url.Parse(%s) failed", l)
			}

			a, err := url.Parse(idpc.AuthUrl)
			if err != nil {
				t.Fatalf("url.Parse(%s) failed", idpc.AuthUrl)
			}
			if loc.Scheme != a.Scheme {
				t.Errorf("Scheme wants %s got %s", a.Scheme, loc.Scheme)
			}
			if loc.Host != a.Host {
				t.Errorf("Host wants %s got %s", a.Host, loc.Host)
			}
			if loc.Path != a.Path {
				t.Errorf("Path wants %s got %s", a.Path, loc.Path)
			}

			q := loc.Query()
			if q.Get("client_id") != idpc.ClientId {
				t.Errorf("client_id wants %s got %s", idpc.ClientId, q.Get("client_id"))
			}

			stateID := q.Get("state")
			state := &pb.ResourceTokenRequestState{}
			err = s.store.Read(storage.ResourceTokenRequestStateDataType, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, state)
			if err != nil {
				t.Fatalf("read ResourceTokenRequestStateDataType failed: %v", err)
			}

			if state.Challenge != loginChallenge {
				t.Errorf("state.Challenge wants %s got %s", loginChallenge, state.Challenge)
			}
			if state.Ttl != tc.wantTTL {
				t.Errorf("state.Ttl wants %d got %d", tc.wantTTL, state.Ttl)
			}
			if len(state.Resources) != tc.wantResourceCount {
				t.Errorf("len(state.Resources) wants %d got %d", tc.wantResourceCount, len(state.Resources))
			}
		})
	}
}

func TestLogin_Hydra_Error(t *testing.T) {
	s, cfg, h, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	ga4ghGCSViewer := url.QueryEscape("https://test.org/dam/master/resources/ga4gh-apis/views/gcs_read/roles/viewer")

	tests := []struct {
		name       string
		authParams string
		respCode   int
	}{
		{
			name:       "max_age wrong format",
			authParams: "max_age=1h&resource=" + ga4ghGCSViewer,
			respCode:   http.StatusBadRequest,
		},
		{
			name:       "negative max_age",
			authParams: "max_age=-1000&resource=" + ga4ghGCSViewer,
			respCode:   http.StatusBadRequest,
		},
		{
			name:       "max_age more than maxTTL",
			authParams: "max_age=9999999&resource=" + ga4ghGCSViewer,
			respCode:   http.StatusBadRequest,
		},
		{
			name:       "negative ttl",
			authParams: "ttl=-1d&resource=" + ga4ghGCSViewer,
			respCode:   http.StatusBadRequest,
		},
		{
			name:       "ttl more than maxTTL",
			authParams: "ttl=100d&resource=" + ga4ghGCSViewer,
			respCode:   http.StatusBadRequest,
		},
		{
			name:       "no resource",
			authParams: "",
			respCode:   http.StatusBadRequest,
		},
		{
			name:       "resource without domain",
			authParams: "resource=dam/master/resources/ga4gh-apis/views/gcs_read/roles/viewer",
			respCode:   http.StatusBadRequest,
		},
		{
			name:       "resource wrong format",
			authParams: "resource=" + strings.ReplaceAll(ga4ghGCSViewer, "resources", "invalid"),
			respCode:   http.StatusBadRequest,
		},
		{
			name:       "resource not exist",
			authParams: "resource=" + strings.ReplaceAll(ga4ghGCSViewer, "ga4gh-apis", "invalid"),
			respCode:   http.StatusNotFound,
		},
		{
			name:       "resource view not exist",
			authParams: "resource=" + strings.ReplaceAll(ga4ghGCSViewer, "gcs_read", "invalid"),
			respCode:   http.StatusNotFound,
		},
		{
			name:       "resource view role not exist",
			authParams: "resource=" + strings.ReplaceAll(ga4ghGCSViewer, "viewer", "invalid"),
			respCode:   http.StatusBadRequest,
		},
		{
			name:       "second resource invalid",
			authParams: "resource=" + ga4ghGCSViewer + "resource=invalid",
			respCode:   http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := sendLogin(s, cfg, h, tc.authParams)
			if resp.StatusCode != tc.respCode {
				t.Errorf("resp.StatusCode wants %d, got %d", tc.respCode, resp.StatusCode)
			}
		})
	}
}

func sendLoggedIn(s *Service, cfg *pb.DamConfig, h *fakehydra.Server, code, state string) (*http.Response, error) {
	// Ensure login state exists before request.
	login := &pb.ResourceTokenRequestState{
		Challenge: loginChallenge,
		Resources: []*pb.ResourceTokenRequestState_Resource{
			{
				Realm:    storage.DefaultRealm,
				Resource: "ga4gh-apis",
				View:     "gcs_read",
				Role:     "viewer",
			},
		},
		Ttl:    int64(time.Hour),
		Broker: testBroker,
	}

	err := s.store.Write(storage.ResourceTokenRequestStateDataType, storage.DefaultRealm, storage.DefaultUser, loginStateID, storage.LatestRev, login, nil)
	if err != nil {
		return nil, err
	}

	// Clear fakehydra server and set reject response.
	h.Clear()
	h.AcceptLoginResp = &hydraapi.RequestHandlerResponse{RedirectTo: hydraURL}

	// Send Request.
	query := fmt.Sprintf("?code=%s&state=%s", code, state)
	u := damURL + loggedInPath + query
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, u, nil)
	s.Handler.ServeHTTP(w, r)

	return w.Result(), nil
}

func TestLoggedIn_Hydra_Success(t *testing.T) {
	s, cfg, h, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	pname := "dr_joe_elixir"

	resp, err := sendLoggedIn(s, cfg, h, pname, loginStateID)
	if err != nil {
		t.Fatalf("sendFinishLogin(s, cfg, h, %s, %s) failed: %v", pname, loginStateID, err)
	}

	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("resp.StatusCode wants %d got %d", http.StatusTemporaryRedirect, resp.StatusCode)
	}

	l := resp.Header.Get("Location")
	if l != hydraURL {
		t.Errorf("Location wants %s got %s", hydraURL, l)
	}

	if *h.AcceptLoginReq.Subject != pname {
		t.Errorf("h.AcceptLoginReq.Subject wants %s got %s", pname, *h.AcceptLoginReq.Subject)
	}

	st, ok := h.AcceptLoginReq.Context[stateIDInHydra]
	if !ok {
		t.Errorf("AcceptLoginReq.Context[%s] not exists", stateIDInHydra)
	}
	stateID, ok := st.(string)
	if !ok {
		t.Errorf("AcceptLoginReq.Context[%s] in wrong type", stateIDInHydra)
	}

	code := &pb.AuthCode{}
	err = s.store.Read(storage.AuthCodeDatatype, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, code)
	if err != nil {
		t.Fatalf("read AuthTokenState failed: %v", err)
	}

	if len(code.State) == 0 {
		t.Errorf("len(code.State) want >0 got 0")
	}

	state := &pb.ResourceTokenRequestState{}
	err = s.store.Read(storage.ResourceTokenRequestStateDataType, storage.DefaultRealm, storage.DefaultUser, code.State, storage.LatestRev, state)
	if err != nil {
		t.Fatalf("read ResourceTokenRequestStateDataType failed: %v", err)
	}

	if len(state.Broker) == 0 {
		t.Errorf("len(state.Broker) want >0 got 0")
	}
}

func TestLoggedIn_Hydra_Errors(t *testing.T) {
	s, cfg, h, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	pname := "dr_joe_elixir"

	tests := []struct {
		name       string
		code       string
		stateID    string
		respStatus int
	}{
		{
			name:       "code invalid",
			code:       "invalid",
			stateID:    loginStateID,
			respStatus: http.StatusServiceUnavailable,
		},
		{
			name:       "stateID invalid",
			code:       pname,
			stateID:    "invalid",
			respStatus: http.StatusServiceUnavailable,
		},
		{
			name:       "user does not have enough permission",
			code:       "dr_joe_era_commons",
			stateID:    loginStateID,
			respStatus: http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := sendLoggedIn(s, cfg, h, tc.code, tc.stateID)
			if err != nil {
				t.Fatalf("sendFinishLogin(s, cfg, h, %s, %s) failed: %v", tc.code, tc.stateID, err)
			}

			if resp.StatusCode != tc.respStatus {
				t.Errorf("resp.StatusCode wants %d got %d", tc.respStatus, resp.StatusCode)
			}
		})
	}
}

func TestHydraConsent(t *testing.T) {
	s, _, h, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientID := "cid"

	h.GetConsentRequestResp = &hydraapi.ConsentRequest{
		Client:  &hydraapi.Client{ClientID: clientID},
		Context: map[string]interface{}{hydra.StateIDKey: consentStateID},
	}
	h.AcceptConsentResp = &hydraapi.RequestHandlerResponse{RedirectTo: hydraURL}

	// Send Request.
	query := fmt.Sprintf("?consent_challenge=%s", consentChallenge)
	u := damURL + hydraConsentPath + query
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, u, nil)
	s.Handler.ServeHTTP(w, r)

	resp := w.Result()

	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("resp.StatusCode wants %d got %d", http.StatusTemporaryRedirect, resp.StatusCode)
	}

	l := resp.Header.Get("Location")
	if l != hydraURL {
		t.Errorf("Location wants %s got %s", hydraURL, l)
	}

	if diff := cmp.Diff(h.AcceptConsentReq.GrantedAudience, []string{clientID}); len(diff) != 0 {
		t.Errorf("GrantedAudience (-want +got): %s", diff)
	}

	if h.AcceptConsentReq.Session.AccessToken["cart"] != consentStateID {
		t.Errorf("AccessToken.cart = %v wants %v", h.AcceptConsentReq.Session.AccessToken["cart"], consentStateID)
	}
}
