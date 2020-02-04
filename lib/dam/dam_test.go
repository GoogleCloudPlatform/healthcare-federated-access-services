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
	"bytes"
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

	"github.com/golang/protobuf/jsonpb" /* copybara-comment */
	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"github.com/google/go-cmp/cmp/cmpopts" /* copybara-comment */
	"github.com/go-openapi/strfmt" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/apis/hydraapi" /* copybara-comment: hydraapi */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds" /* copybara-comment: clouds */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/hydra" /* copybara-comment: hydra */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/persona" /* copybara-comment: persona */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakehydra" /* copybara-comment: fakehydra */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakeoidcissuer" /* copybara-comment: fakeoidcissuer */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/httptestclient" /* copybara-comment: httptestclient */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test" /* copybara-comment: test */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/testhttp" /* copybara-comment: testhttp */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
)

const (
	damURL           = "https://dam.example.com"
	hydraAdminURL    = "https://admin.hydra.example.com"
	hydraPublicURL   = "https://hydra.example.com/"
	testBroker       = "testBroker"
	useHydra         = true
	loginChallenge   = "lc-1234"
	loginStateID     = "ls-1234"
	consentChallenge = "cc-1234"
	consentStateID   = "cs-1234"
)

var (
	defaultScope         = "openid offline ga4gh_passport_v1 profile email identities account_admin"
	defaultGrantTypes    = []string{"authorization_code"}
	defaultResponseTypes = []string{"token", "code", "id_token"}
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
	server, err := fakeoidcissuer.New(hydraPublicURL, &testkeys.PersonaBrokerKey, "dam", "testdata/config", false)
	if err != nil {
		t.Fatalf("fakeoidcissuer.New(%q, _, _) failed: %v", hydraPublicURL, err)
	}
	s := NewService(&Options{
		HTTPClient:     server.Client(),
		Domain:         "test.org",
		DefaultBroker:  "no-broker",
		Store:          store,
		Warehouse:      wh,
		UseHydra:       useHydra,
		HydraAdminURL:  hydraAdminURL,
		HydraPublicURL: hydraPublicURL,
	})
	tests := []test.HandlerTest{
		// Realm tests.
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
			Input: `{"item":{"interfaces":{"gcp:gs":"gs://${bucket}"},"ui":{"label":"foo","description":"bar"}, "roles": {
        "viewer": {
          "targetRoles": ["roles/storage.objectViewer"],
          "targetScopes": [
            "https://www.googleapis.com/auth/cloud-platform"
          ],
          "damRoleCategories": ["metadata", "list", "read"],
          "ui": {
            "label": "File Viewer",
            "description": "List and read files"
          }
        }
			}}}`,
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
	}
	test.HandlerTests(t, s.Handler, tests, hydraPublicURL, server.Config())
}

func TestMinConfig(t *testing.T) {
	store := storage.NewMemoryStorage("dam-min", "testdata/config")
	server, err := fakeoidcissuer.New(hydraPublicURL, &testkeys.PersonaBrokerKey, "dam-min", "testdata/config", false)
	if err != nil {
		t.Fatalf("fakeoidcissuer.New(%q, _, _) failed: %v", hydraPublicURL, err)
	}
	s := NewService(&Options{
		HTTPClient:     server.Client(),
		Domain:         "test.org",
		DefaultBroker:  "no-broker",
		Store:          store,
		Warehouse:      nil,
		UseHydra:       useHydra,
		HydraAdminURL:  hydraAdminURL,
		HydraPublicURL: hydraPublicURL,
	})
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
	test.HandlerTests(t, s.Handler, tests, hydraPublicURL, server.Config())
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
	server, err := fakeoidcissuer.New(hydraPublicURL, &testkeys.PersonaBrokerKey, "dam", "testdata/config", false)
	if err != nil {
		t.Fatalf("fakeoidcissuer.New(%q, _, _) failed: %v", hydraPublicURL, err)
	}
	ctx := server.ContextWithClient(context.Background())
	s := NewService(&Options{
		Domain:         "test.org",
		DefaultBroker:  "no-broker",
		Store:          store,
		Warehouse:      nil,
		UseHydra:       useHydra,
		HydraAdminURL:  hydraAdminURL,
		HydraPublicURL: hydraPublicURL,
	})

	realm := "master"
	cfg, err := s.loadConfig(nil, realm)
	if err != nil {
		t.Fatalf("cannot load config, %v", err)
	}

	pname := "dr_joe_elixir"
	p := cfg.TestPersonas[pname]
	acTok, _, err := persona.NewAccessToken(pname, hydraPublicURL, test.TestClientID, persona.DefaultScope, p)
	if err != nil {
		t.Fatalf("persona.NewAccessToken(%q, %q, _, _) failed: %v", pname, hydraPublicURL, err)
	}

	resName := "ga4gh-apis"
	viewName := "gcs_read"
	role := "viewer"
	ttl := time.Hour

	id, err := s.upstreamTokenToPassportIdentity(ctx, cfg, nil, string(acTok), test.TestClientID)
	if err != nil {
		t.Fatalf("unable to obtain passport identity: %v", err)
	}

	status, err := s.checkAuthorization(ctx, id, ttl, resName, viewName, role, cfg, test.TestClientID)
	if status != http.StatusOK || err != nil {
		t.Errorf("checkAuthorization(id, %v, %q, %q, %q, cfg, %q) failed, expected %q, got %q: %v", ttl, resName, viewName, role, test.TestClientID, http.StatusOK, status, err)
	}

	// TODO: we need more tests for other condition in checkAuthorization()
}

func setupHydraTest() (*Service, *pb.DamConfig, *pb.DamSecrets, *fakehydra.Server, *persona.Server, error) {
	store := storage.NewMemoryStorage("dam", "testdata/config")
	broker, err := persona.NewBroker(hydraPublicURL, &testkeys.PersonaBrokerKey, "dam", "testdata/config", false)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("fakeoidcissuer.New(%q, _, _) failed: %v", hydraPublicURL, err)
	}

	h := fakehydra.New(broker.Handler)

	wh := clouds.NewMockTokenCreator(false)
	s := NewService(&Options{
		HTTPClient:     httptestclient.New(broker.Handler),
		Domain:         "https://test.org",
		DefaultBroker:  testBroker,
		Store:          store,
		Warehouse:      wh,
		UseHydra:       useHydra,
		HydraAdminURL:  hydraAdminURL,
		HydraPublicURL: hydraPublicURL,
	})

	cfg, err := s.loadConfig(nil, storage.DefaultRealm)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	sec, err := s.loadSecrets(nil)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	return s, cfg, sec, h, broker, nil
}

func sendLogin(s *Service, cfg *pb.DamConfig, h *fakehydra.Server, authParams string, scope []string) *http.Response {
	h.GetLoginRequestResp = &hydraapi.LoginRequest{
		Challenge:      loginChallenge,
		RequestURL:     hydraPublicURL + "/oauth2/auth?" + authParams,
		RequestedScope: scope,
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
	s, cfg, _, h, _, err := setupHydraTest()
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
			resp := sendLogin(s, cfg, h, tc.authParams, nil)
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
			if state.Type != pb.ResourceTokenRequestState_DATASET {
				t.Errorf("state.Type wants %v got %v", pb.ResourceTokenRequestState_DATASET, state.Type)
			}
		})
	}
}

func TestLogin_Hydra_Error(t *testing.T) {
	s, cfg, _, h, _, err := setupHydraTest()
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
			resp := sendLogin(s, cfg, h, tc.authParams, nil)
			if resp.StatusCode != tc.respCode {
				t.Errorf("resp.StatusCode wants %d, got %d", tc.respCode, resp.StatusCode)
			}
		})
	}
}

func TestLogin_LoginHint_Hydra_Success(t *testing.T) {
	s, cfg, _, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	resp := sendLogin(s, cfg, h, "login_hint=idp:foo@bar.com", []string{"openid", "identities", "offline"})
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
	wantLoginHint := "idp:foo@bar.com"
	if q.Get("login_hint") != wantLoginHint {
		t.Errorf("login_hint = %s wants %s", q.Get("login_hint"), wantLoginHint)
	}
}

func TestLogin_Endpoint_Hydra_Success(t *testing.T) {
	s, cfg, _, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	resp := sendLogin(s, cfg, h, "", []string{"openid", "identities", "offline"})
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

	if state.Type != pb.ResourceTokenRequestState_ENDPOINT {
		t.Errorf("state.Type wants %v got %v", pb.ResourceTokenRequestState_ENDPOINT, state.Type)
	}
}

func sendLoggedIn(t *testing.T, s *Service, cfg *pb.DamConfig, h *fakehydra.Server, code, state string, tokenType pb.ResourceTokenRequestState_TokenType) *http.Response {
	t.Helper()

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
		Realm:  storage.DefaultRealm,
		Type:   tokenType,
	}

	err := s.store.Write(storage.ResourceTokenRequestStateDataType, storage.DefaultRealm, storage.DefaultUser, loginStateID, storage.LatestRev, login, nil)
	if err != nil {
		t.Fatalf("store.Write loginState failed: %v", err)
	}

	// Clear fakehydra server and set reject response.
	h.Clear()
	h.AcceptLoginResp = &hydraapi.RequestHandlerResponse{RedirectTo: hydraPublicURL}

	// Send Request.
	query := fmt.Sprintf("?code=%s&state=%s", code, state)
	u := damURL + loggedInPath + query
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, u, nil)

	s.Handler.ServeHTTP(w, r)

	return w.Result()
}

func TestLoggedIn_Hydra_Success(t *testing.T) {
	s, cfg, _, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	pname := "dr_joe_elixir"

	resp := sendLoggedIn(t, s, cfg, h, pname, loginStateID, pb.ResourceTokenRequestState_DATASET)

	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("resp.StatusCode wants %d got %d", http.StatusTemporaryRedirect, resp.StatusCode)
	}

	l := resp.Header.Get("Location")
	if l != hydraPublicURL {
		t.Errorf("Location wants %s got %s", hydraPublicURL, l)
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
	if _, ok := h.AcceptLoginReq.Context["identities"]; ok {
		t.Errorf("AcceptLoginReq.Context[identities] should not exists")
	}

	state := &pb.ResourceTokenRequestState{}
	err = s.store.Read(storage.ResourceTokenRequestStateDataType, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, state)
	if err != nil {
		t.Fatalf("read ResourceTokenRequestStateDataType failed: %v", err)
	}

	if len(state.Broker) == 0 {
		t.Errorf("len(state.Broker) want >0 got 0")
	}
}

func TestLoggedIn_Hydra_Errors(t *testing.T) {
	s, cfg, _, h, _, err := setupHydraTest()
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
			resp := sendLoggedIn(t, s, cfg, h, tc.code, tc.stateID, pb.ResourceTokenRequestState_DATASET)

			if resp.StatusCode != tc.respStatus {
				t.Errorf("resp.StatusCode wants %d got %d", tc.respStatus, resp.StatusCode)
			}
		})
	}
}

func TestLoggedIn_Endpoint_Hydra_Success(t *testing.T) {
	s, cfg, _, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	pname := "dr_joe_elixir"

	resp := sendLoggedIn(t, s, cfg, h, pname, loginStateID, pb.ResourceTokenRequestState_ENDPOINT)

	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("resp.StatusCode wants %d got %d", http.StatusTemporaryRedirect, resp.StatusCode)
	}

	l := resp.Header.Get("Location")
	if l != hydraPublicURL {
		t.Errorf("Location wants %s got %s", hydraPublicURL, l)
	}

	if *h.AcceptLoginReq.Subject != pname {
		t.Errorf("h.AcceptLoginReq.Subject wants %s got %s", pname, *h.AcceptLoginReq.Subject)
	}

	wantReqContext := map[string]interface{}{
		"identities": []interface{}{"dr_joe_elixir", "dr_joe@faculty.example.edu"},
	}

	if diff := cmp.Diff(wantReqContext, h.AcceptLoginReq.Context); len(diff) > 0 {
		t.Errorf("AcceptLoginReq.Context (-want, +got): %s", diff)
	}
}

func TestHydraConsent(t *testing.T) {
	s, _, _, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientID := "cid"

	h.GetConsentRequestResp = &hydraapi.ConsentRequest{
		Client:  &hydraapi.Client{ClientID: clientID},
		Context: map[string]interface{}{hydra.StateIDKey: consentStateID},
	}
	h.AcceptConsentResp = &hydraapi.RequestHandlerResponse{RedirectTo: hydraPublicURL}

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
	if l != hydraPublicURL {
		t.Errorf("Location wants %s got %s", hydraPublicURL, l)
	}

	if diff := cmp.Diff(h.AcceptConsentReq.GrantedAudience, []string{clientID}); len(diff) != 0 {
		t.Errorf("GrantedAudience (-want +got): %s", diff)
	}

	if h.AcceptConsentReq.Session.AccessToken["cart"] != consentStateID {
		t.Errorf("AccessToken.cart = %v wants %v", h.AcceptConsentReq.Session.AccessToken["cart"], consentStateID)
	}
}

func TestHydraConsent_Endpoint(t *testing.T) {
	s, _, _, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientID := "cid"

	h.GetConsentRequestResp = &hydraapi.ConsentRequest{
		Client: &hydraapi.Client{ClientID: clientID},
		Context: map[string]interface{}{
			"identities": []interface{}{"a@example.com", "b@example.com"},
		},
	}
	h.AcceptConsentResp = &hydraapi.RequestHandlerResponse{RedirectTo: hydraPublicURL}

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
	if l != hydraPublicURL {
		t.Errorf("Location wants %s got %s", hydraPublicURL, l)
	}

	if diff := cmp.Diff(h.AcceptConsentReq.GrantedAudience, []string{clientID}); len(diff) != 0 {
		t.Errorf("GrantedAudience (-want +got): %s", diff)
	}

	wantIdentities := []interface{}{"a@example.com", "b@example.com"}

	if diff := cmp.Diff(wantIdentities, h.AcceptConsentReq.Session.AccessToken["identities"]); len(diff) > 0 {
		t.Errorf("AccessToken.identities (-want, +got): %s", diff)
	}
}

func sendResourceTokens(t *testing.T, s *Service) *http.Response {
	t.Helper()

	state := &pb.ResourceTokenRequestState{
		Challenge: loginChallenge,
		Resources: []*pb.ResourceTokenRequestState_Resource{
			{
				Realm:    storage.DefaultRealm,
				Resource: "ga4gh-apis",
				View:     "gcs_read",
				Role:     "viewer",
			},
		},
		Ttl:          int64(time.Hour),
		Broker:       testBroker,
		Issuer:       hydraPublicURL,
		Subject:      "subject",
		EpochSeconds: time.Now().Unix(),
	}
	err := s.store.Write(storage.ResourceTokenRequestStateDataType, storage.DefaultRealm, storage.DefaultUser, consentStateID, storage.LatestRev, state, nil)
	if err != nil {
		t.Fatalf("Write state failed: %v", err)
	}

	q := url.Values{
		"client_id":     []string{test.TestClientID},
		"client_secret": []string{test.TestClientSecret},
	}
	header := http.Header{"Authorization": []string{"Bearer this_is_a_token"}}
	return testhttp.SendTestRequest(t, s.Handler, http.MethodPost, resourceTokensPath, q, nil, header)
}

func TestResourceTokens(t *testing.T) {
	s, _, _, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	h.IntrospectionResp = &hydraapi.Introspection{
		Extra: map[string]interface{}{"cart": consentStateID},
	}

	resp := sendResourceTokens(t, s)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, wants %d", resp.StatusCode, http.StatusOK)
	}
}

func TestResourceTokens_HydraError(t *testing.T) {
	s, _, _, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	n := "token expired"
	h.IntrospectionErr = &hydraapi.GenericError{
		Code: http.StatusUnauthorized,
		Name: &n,
	}

	resp := sendResourceTokens(t, s)
	// TODO: Should convert Hydra API error to grpc status.
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, wants %d", resp.StatusCode, http.StatusInternalServerError)
	}
}

func TestResourceTokens_CartNotExistsInToken(t *testing.T) {
	s, _, _, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	h.IntrospectionResp = &hydraapi.Introspection{}
	resp := sendResourceTokens(t, s)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, wants %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func TestResourceTokens_CartNotExistsInStorage(t *testing.T) {
	s, _, _, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	h.IntrospectionResp = &hydraapi.Introspection{
		Extra: map[string]interface{}{"cart": "invalid"},
	}

	resp := sendResourceTokens(t, s)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, wants %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func sendClientsGet(t *testing.T, pname, clientName, clientID, clientSecret string, s *Service, iss *persona.Server) *http.Response {
	t.Helper()

	var p *cpb.TestPersona
	if iss.Config() != nil {
		p = iss.Config().TestPersonas[pname]
	}

	tok, _, err := persona.NewAccessToken(pname, hydraPublicURL, clientID, noScope, p)
	if err != nil {
		t.Fatalf("persona.NewAccessToken(%q, %q, _, _) failed: %v", pname, hydraPublicURL, err)
	}

	path := strings.ReplaceAll(clientPath, "{realm}", "test")
	path = strings.ReplaceAll(path, "{name}", clientName)
	q := url.Values{
		"client_id":     []string{clientID},
		"client_secret": []string{clientSecret},
	}
	h := http.Header{"Authorization": []string{"Bearer " + string(tok)}}
	return testhttp.SendTestRequest(t, s.Handler, http.MethodGet, path, q, nil, h)
}

func TestClients_Get(t *testing.T) {
	s, cfg, sec, _, iss, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientName := "test_client"
	pname := "non-admin"
	cli := cfg.Clients[clientName]

	resp := sendClientsGet(t, pname, clientName, cli.ClientId, sec.ClientSecrets[cli.ClientId], s, iss)

	got := &cpb.ClientResponse{}
	if err := jsonpb.Unmarshal(resp.Body, got); err != nil && err != io.EOF {
		t.Fatalf("jsonpb.Unmarshal() failed: %v", err)
	}

	want := &cpb.ClientResponse{Client: cli}

	if diff := cmp.Diff(want, got, protocmp.Transform()); len(diff) > 0 {
		t.Errorf("response (-want, +got): %s", diff)
	}
}

func TestClients_Get_Error(t *testing.T) {
	s, _, _, _, iss, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	tests := []struct {
		name       string
		clientName string
		status     int
	}{
		{
			name:       "client not exists",
			clientName: "invalid",
			status:     http.StatusNotFound,
		},
		{
			name:       "client id and client name not match",
			clientName: "test_client2",
			status:     http.StatusNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pname := "non-admin"

			resp := sendClientsGet(t, pname, tc.clientName, test.TestClientID, test.TestClientSecret, s, iss)

			if resp.StatusCode != tc.status {
				t.Errorf("resp.StatusCode = %d, wants %d", resp.StatusCode, tc.status)
			}
		})
	}
}

func sendConfigClientsGet(t *testing.T, pname, clientName, clientID, clientSecret string, s *Service, iss *persona.Server) *http.Response {
	t.Helper()

	var p *cpb.TestPersona
	if iss.Config() != nil {
		p = iss.Config().TestPersonas[pname]
	}

	tok, _, err := persona.NewAccessToken(pname, hydraPublicURL, clientID, noScope, p)
	if err != nil {
		t.Fatalf("persona.NewAccessToken(%q, %q, _, _) failed: %v", pname, hydraPublicURL, err)
	}

	path := strings.ReplaceAll(configClientPath, "{realm}", "test")
	path = strings.ReplaceAll(path, "{name}", clientName)
	q := url.Values{
		"client_id":     []string{clientID},
		"client_secret": []string{clientSecret},
	}
	h := http.Header{"Authorization": []string{"Bearer " + string(tok)}}
	return testhttp.SendTestRequest(t, s.Handler, http.MethodGet, path, q, nil, h)
}

func TestConfigClients_Get(t *testing.T) {
	s, cfg, sec, _, iss, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientName := "test_client"
	pname := "admin"
	cli := cfg.Clients[clientName]

	resp := sendConfigClientsGet(t, pname, clientName, cli.ClientId, sec.ClientSecrets[cli.ClientId], s, iss)

	got := &cpb.ConfigClientResponse{}
	if err := jsonpb.Unmarshal(resp.Body, got); err != nil && err != io.EOF {
		t.Fatalf("jsonpb.Unmarshal() failed: %v", err)
	}

	want := &cpb.ConfigClientResponse{Client: cli}

	if diff := cmp.Diff(want, got, protocmp.Transform()); len(diff) > 0 {
		t.Errorf("response (-want, +got): %s", diff)
	}
}

func TestConfigClients_Get_Error(t *testing.T) {
	s, _, _, _, iss, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	tests := []struct {
		name       string
		persona    string
		clientName string
		status     int
	}{
		{
			name:       "client not exists",
			persona:    "admin",
			clientName: "invalid",
			status:     http.StatusNotFound,
		},
		{
			name:       "not admin",
			persona:    "non-admin",
			clientName: "test_client",
			status:     http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := sendConfigClientsGet(t, tc.persona, tc.clientName, test.TestClientID, test.TestClientSecret, s, iss)

			if resp.StatusCode != tc.status {
				t.Errorf("resp.StatusCode = %d, wants %d", resp.StatusCode, tc.status)
			}
		})
	}
}

func diffOfHydraClientIgnoreClientIDAndSecret(c1 *hydraapi.Client, c2 *hydraapi.Client) string {
	return cmp.Diff(c1, c2, cmpopts.IgnoreFields(hydraapi.Client{}, "ClientID", "Secret"), cmpopts.IgnoreUnexported(strfmt.DateTime{}))
}

func sendConfigClientsCreate(t *testing.T, pname, clientName, clientID, clientSecret string, cli *cpb.Client, s *Service, iss *persona.Server) *http.Response {
	t.Helper()

	var p *cpb.TestPersona
	if iss.Config() != nil {
		p = iss.Config().TestPersonas[pname]
	}

	tok, _, err := persona.NewAccessToken(pname, hydraPublicURL, clientID, noScope, p)
	if err != nil {
		t.Fatalf("persona.NewAccessToken(%q, %q, _, _) failed: %v", pname, hydraPublicURL, err)
	}

	m := jsonpb.Marshaler{}
	var buf bytes.Buffer
	if err := m.Marshal(&buf, &cpb.ConfigClientRequest{Item: cli}); err != nil {
		t.Fatal(err)
	}

	path := strings.ReplaceAll(configClientPath, "{realm}", "test")
	path = strings.ReplaceAll(path, "{name}", clientName)
	q := url.Values{
		"client_id":     []string{clientID},
		"client_secret": []string{clientSecret},
	}
	h := http.Header{"Authorization": []string{"Bearer " + string(tok)}}
	return testhttp.SendTestRequest(t, s.Handler, http.MethodPost, path, q, &buf, h)
}

func TestConfigClients_Create_Success(t *testing.T) {
	s, _, _, h, iss, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientName := "new_client"
	newClientID := "00000000-0000-0000-0000-100000000000"

	cli := &cpb.Client{
		RedirectUris: []string{"http://client.example.com"},
		Ui: map[string]string{
			"label":       "l",
			"description": "d",
		},
	}

	pname := "admin"

	h.CreateClientResp = &hydraapi.Client{
		ClientID:      newClientID,
		Name:          clientName,
		Secret:        "secret",
		RedirectURIs:  cli.RedirectUris,
		Scope:         defaultScope,
		GrantTypes:    defaultGrantTypes,
		ResponseTypes: defaultResponseTypes,
	}

	resp := sendConfigClientsCreate(t, pname, clientName, test.TestClientID, test.TestClientSecret, cli, s, iss)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status=%d, wants %d", resp.StatusCode, http.StatusOK)
	}

	got := &cpb.ConfigClientResponse{}
	if err := jsonpb.Unmarshal(resp.Body, got); err != nil && err != io.EOF {
		t.Fatalf("jsonpb.Unmarshal() failed: %v", err)
	}

	if got.ClientSecret != h.CreateClientResp.Secret {
		t.Errorf("got.ClientSecret = %s, wants %s", got.ClientSecret, h.CreateClientResp.Secret)
	}

	if len(h.CreateClientReq.ClientID) == 0 {
		t.Errorf("should pass client id in hydra request")
	}

	if len(h.CreateClientReq.Secret) == 0 {
		t.Errorf("should pass secret in hydra request")
	}

	wantReq := &hydraapi.Client{
		Name:          clientName,
		GrantTypes:    defaultGrantTypes,
		ResponseTypes: defaultResponseTypes,
		Scope:         defaultScope,
		RedirectURIs:  cli.RedirectUris,
	}
	if diff := diffOfHydraClientIgnoreClientIDAndSecret(wantReq, h.CreateClientReq); len(diff) > 0 {
		t.Errorf("client (-want, +got): %s", diff)
	}

	wantResp := &cpb.ConfigClientResponse{
		Client: &cpb.Client{
			ClientId:      newClientID,
			Ui:            cli.Ui,
			RedirectUris:  cli.RedirectUris,
			Scope:         defaultScope,
			GrantTypes:    defaultGrantTypes,
			ResponseTypes: defaultResponseTypes,
		},
		ClientSecret: "secret",
	}

	if diff := cmp.Diff(wantResp, got, protocmp.Transform()); len(diff) > 0 {
		t.Errorf("response (-want, +got): %s", diff)
	}
}

func TestConfigClients_Create_Success_Storage(t *testing.T) {
	s, _, _, h, iss, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientName := "new_client"
	newClientID := "00000000-0000-0000-0000-100000000000"

	cli := &cpb.Client{
		RedirectUris: []string{"http://client.example.com"},
		Ui: map[string]string{
			"label":       "l",
			"description": "d",
		},
	}

	pname := "admin"

	h.CreateClientResp = &hydraapi.Client{
		ClientID:      newClientID,
		Name:          clientName,
		Secret:        "secret",
		RedirectURIs:  cli.RedirectUris,
		Scope:         defaultScope,
		GrantTypes:    defaultGrantTypes,
		ResponseTypes: defaultResponseTypes,
	}

	resp := sendConfigClientsCreate(t, pname, clientName, test.TestClientID, test.TestClientSecret, cli, s, iss)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status=%d, wants %d", resp.StatusCode, http.StatusOK)
	}

	conf, err := s.loadConfig(nil, "test")
	if err != nil {
		t.Fatalf("s.loadConfig() failed %v", err)
	}
	created, ok := conf.Clients[clientName]
	if !ok {
		t.Errorf("conf.Clients[%s] should exists in storage", clientName)
	}

	sec, err := s.loadSecrets(nil)
	if err != nil {
		t.Fatalf("s.loadSecrets() failed %v", err)
	}
	if sec.ClientSecrets[created.ClientId] != h.CreateClientResp.Secret {
		t.Errorf("client secret in storage = %s, wants %s", sec.ClientSecrets[created.ClientId], h.CreateClientResp.Secret)
	}
}

func TestConfigClients_Create_Error(t *testing.T) {
	s, _, _, h, iss, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientName := "new_client"
	newClientID := "00000000-0000-0000-0000-100000000000"

	cli := &cpb.Client{
		RedirectUris: []string{"http://client.example.com"},
		Ui: map[string]string{
			"label":       "l",
			"description": "d",
		},
	}

	tests := []struct {
		name       string
		persona    string
		clientName string
		client     *cpb.Client
		status     int
	}{
		{
			name:       "client exists",
			persona:    "admin",
			clientName: "test_client",
			client:     cli,
			status:     http.StatusConflict,
		},
		{
			name:       "not admin",
			persona:    "non-admin",
			clientName: clientName,
			client:     cli,
			status:     http.StatusForbidden,
		},
		{
			name:       "no redirect",
			persona:    "admin",
			clientName: clientName,
			client:     &cpb.Client{Ui: cli.Ui},
			status:     http.StatusBadRequest,
		},
		{
			name:       "no ui",
			persona:    "admin",
			clientName: clientName,
			client:     &cpb.Client{RedirectUris: cli.RedirectUris},
			status:     http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h.Clear()
			h.CreateClientResp = &hydraapi.Client{
				ClientID: newClientID,
				Name:     clientName,
				Secret:   "secret",
			}

			resp := sendConfigClientsCreate(t, tc.persona, tc.clientName, test.TestClientID, test.TestClientSecret, tc.client, s, iss)

			if resp.StatusCode != tc.status {
				t.Errorf("resp.StatusCode = %d, wants %d", resp.StatusCode, tc.status)
			}

			if h.CreateClientReq != nil {
				t.Errorf("should not call create client to hydra")
			}

			conf, err := s.loadConfig(nil, "test")
			if err != nil {
				t.Fatalf("s.loadConfig() failed %v", err)
			}
			if _, ok := conf.Clients[clientName]; ok {
				t.Errorf("conf.Clients[%s] should not exists in storage", clientName)
			}
		})
	}
}

func TestConfigClients_Create_Hydra_Error(t *testing.T) {
	s, _, _, h, iss, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientName := "new_client"
	newClientID := "00000000-0000-0000-0000-100000000000"

	cli := &cpb.Client{
		RedirectUris: []string{"http://client.example.com"},
		Ui: map[string]string{
			"label":       "l",
			"description": "d",
		},
	}

	h.CreateClientResp = &hydraapi.Client{
		ClientID:      newClientID,
		Name:          clientName,
		Secret:        "secret",
		RedirectURIs:  cli.RedirectUris,
		Scope:         defaultScope,
		GrantTypes:    defaultGrantTypes,
		ResponseTypes: defaultResponseTypes,
	}
	h.CreateClientErr = &hydraapi.GenericError{Code: http.StatusServiceUnavailable}

	resp := sendConfigClientsCreate(t, "admin", clientName, test.TestClientID, test.TestClientSecret, cli, s, iss)

	// TODO should use better http status.
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("resp.StatusCode = %d, wants %d", resp.StatusCode, http.StatusBadRequest)
	}

	conf, err := s.loadConfig(nil, "test")
	if err != nil {
		t.Fatalf("s.loadConfig() failed %v", err)
	}
	if _, ok := conf.Clients[clientName]; ok {
		t.Errorf("conf.Clients[%s] should not exists in storage", clientName)
	}
}

func sendConfigClientsUpdate(t *testing.T, pname, clientName, clientID, clientSecret string, cli *cpb.Client, s *Service, iss *persona.Server) *http.Response {
	t.Helper()

	var p *cpb.TestPersona
	if iss.Config() != nil {
		p = iss.Config().TestPersonas[pname]
	}

	tok, _, err := persona.NewAccessToken(pname, hydraPublicURL, clientID, noScope, p)
	if err != nil {
		t.Fatalf("persona.NewAccessToken(%q, %q, _, _) failed: %v", pname, hydraPublicURL, err)
	}

	m := jsonpb.Marshaler{}
	var buf bytes.Buffer
	if err := m.Marshal(&buf, &cpb.ConfigClientRequest{Item: cli}); err != nil {
		t.Fatal(err)
	}

	path := strings.ReplaceAll(configClientPath, "{realm}", "test")
	path = strings.ReplaceAll(path, "{name}", clientName)
	q := url.Values{
		"client_id":     []string{clientID},
		"client_secret": []string{clientSecret},
	}
	h := http.Header{"Authorization": []string{"Bearer " + string(tok)}}
	return testhttp.SendTestRequest(t, s.Handler, http.MethodPatch, path, q, &buf, h)
}

func TestConfigClients_Update_Success(t *testing.T) {
	s, cfg, sec, h, iss, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientName := "test_client"

	before := cfg.Clients[clientName]

	beforeSec := sec.ClientSecrets[before.ClientId]

	// Update the client RedirectUris.
	cli := &cpb.Client{
		RedirectUris: []string{"http://client.example.com"},
	}

	pname := "admin"

	h.UpdateClientResp = &hydraapi.Client{
		ClientID:      test.TestClientID,
		Name:          clientName,
		Secret:        "secret",
		RedirectURIs:  cli.RedirectUris,
		Scope:         defaultScope,
		GrantTypes:    defaultGrantTypes,
		ResponseTypes: defaultResponseTypes,
	}

	resp := sendConfigClientsUpdate(t, pname, clientName, test.TestClientID, test.TestClientSecret, cli, s, iss)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status=%d, wants %d", resp.StatusCode, http.StatusOK)
	}

	got := &cpb.ConfigClientResponse{}
	if err := jsonpb.Unmarshal(resp.Body, got); err != nil && err != io.EOF {
		t.Fatalf("jsonpb.Unmarshal() failed: %v", err)
	}

	if got.ClientSecret != h.UpdateClientResp.Secret {
		t.Errorf("got.ClientSecret = %s, wants %s", got.ClientSecret, h.UpdateClientResp.Secret)
	}

	if got.ClientSecret == beforeSec {
		t.Errorf("client secret should updated")
	}

	if len(h.UpdateClientReq.ClientID) == 0 {
		t.Errorf("should pass client id in hydra request")
	}

	if len(h.UpdateClientReq.Secret) == 0 {
		t.Errorf("should pass secret in hydra request")
	}
}

func TestConfigClients_Update_Success_Storage(t *testing.T) {
	s, _, _, h, iss, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientName := "test_client"

	// Update the client RedirectUris.
	cli := &cpb.Client{
		RedirectUris: []string{"http://client.example.com"},
	}

	pname := "admin"

	h.UpdateClientResp = &hydraapi.Client{
		ClientID:      test.TestClientID,
		Name:          clientName,
		Secret:        "secret",
		RedirectURIs:  cli.RedirectUris,
		Scope:         defaultScope,
		GrantTypes:    defaultGrantTypes,
		ResponseTypes: defaultResponseTypes,
	}

	resp := sendConfigClientsUpdate(t, pname, clientName, test.TestClientID, test.TestClientSecret, cli, s, iss)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status=%d, wants %d", resp.StatusCode, http.StatusOK)
	}

	conf, err := s.loadConfig(nil, "test")
	if err != nil {
		t.Fatalf("s.loadConfig() failed %v", err)
	}
	updated, ok := conf.Clients[clientName]
	if !ok {
		t.Errorf("conf.Clients[%s] should exists in storage", clientName)
	}

	sec, err := s.loadSecrets(nil)
	if err != nil {
		t.Fatalf("s.loadSecrets() failed %v", err)
	}
	if sec.ClientSecrets[updated.ClientId] != h.UpdateClientResp.Secret {
		t.Errorf("client secret in storage = %s, wants %s", sec.ClientSecrets[updated.ClientId], h.UpdateClientResp.Secret)
	}
}

func TestConfigClients_Update_Error(t *testing.T) {
	s, cfg, _, h, iss, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientName := "test_client"
	// Update the client RedirectUris.
	cli := &cpb.Client{
		RedirectUris: []string{"http://client.example.com"},
	}

	tests := []struct {
		name       string
		persona    string
		clientName string
		status     int
	}{
		{
			name:       "client not exists",
			persona:    "admin",
			clientName: "invalid",
			status:     http.StatusNotFound,
		},
		{
			name:       "not admin",
			persona:    "non-admin",
			clientName: clientName,
			status:     http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h.Clear()
			h.UpdateClientResp = &hydraapi.Client{
				ClientID:      test.TestClientID,
				Name:          clientName,
				Secret:        "secret",
				RedirectURIs:  cli.RedirectUris,
				Scope:         defaultScope,
				GrantTypes:    defaultGrantTypes,
				ResponseTypes: defaultResponseTypes,
			}

			resp := sendConfigClientsUpdate(t, tc.persona, tc.clientName, test.TestClientID, test.TestClientSecret, cli, s, iss)

			if resp.StatusCode != tc.status {
				t.Errorf("resp.StatusCode = %d, wants %d", resp.StatusCode, tc.status)
			}

			if h.UpdateClientReq != nil {
				t.Errorf("should not call Update client to hydra")
			}

			conf, err := s.loadConfig(nil, "test")
			if err != nil {
				t.Fatalf("s.loadConfig() failed %v", err)
			}
			if diff := cmp.Diff(cfg, conf, protocmp.Transform()); len(diff) != 0 {
				t.Errorf("config should not update, (-want, +got): %s", diff)
			}
		})
	}
}

func TestConfigClients_Update_Hydra_Error(t *testing.T) {
	s, cfg, _, h, iss, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientName := "test_client"
	// Update the client RedirectUris.
	cli := &cpb.Client{
		RedirectUris: []string{"http://client.example.com"},
	}

	h.UpdateClientResp = &hydraapi.Client{
		ClientID:      test.TestClientID,
		Name:          clientName,
		Secret:        "secret",
		RedirectURIs:  cli.RedirectUris,
		Scope:         defaultScope,
		GrantTypes:    defaultGrantTypes,
		ResponseTypes: defaultResponseTypes,
	}
	h.UpdateClientErr = &hydraapi.GenericError{Code: http.StatusServiceUnavailable}

	resp := sendConfigClientsUpdate(t, "admin", clientName, test.TestClientID, test.TestClientSecret, cli, s, iss)

	// TODO should use better http status.
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("resp.StatusCode = %d, wants %d", resp.StatusCode, http.StatusBadRequest)
	}

	conf, err := s.loadConfig(nil, "test")
	if err != nil {
		t.Fatalf("s.loadConfig() failed %v", err)
	}
	if diff := cmp.Diff(cfg, conf, protocmp.Transform()); len(diff) != 0 {
		t.Errorf("config should not update, (-want, +got): %s", diff)
	}
}

func sendConfigClientsDelete(t *testing.T, pname, clientName, clientID, clientSecret string, s *Service, iss *persona.Server) *http.Response {
	t.Helper()

	var p *cpb.TestPersona
	if iss.Config() != nil {
		p = iss.Config().TestPersonas[pname]
	}

	tok, _, err := persona.NewAccessToken(pname, hydraPublicURL, clientID, noScope, p)
	if err != nil {
		t.Fatalf("persona.NewAccessToken(%q, %q, _, _) failed: %v", pname, hydraPublicURL, err)
	}

	path := strings.ReplaceAll(configClientPath, "{realm}", "test")
	path = strings.ReplaceAll(path, "{name}", clientName)
	q := url.Values{
		"client_id":     []string{clientID},
		"client_secret": []string{clientSecret},
	}
	h := http.Header{"Authorization": []string{"Bearer " + string(tok)}}
	return testhttp.SendTestRequest(t, s.Handler, http.MethodDelete, path, q, nil, h)
}

func TestConfigClients_Delete_Success(t *testing.T) {
	s, _, _, _, iss, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientName := "test_client"

	pname := "admin"

	resp := sendConfigClientsDelete(t, pname, clientName, test.TestClientID, test.TestClientSecret, s, iss)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("resp.StatusCode = %d, wants %d", resp.StatusCode, http.StatusOK)
	}

	conf, err := s.loadConfig(nil, "test")
	if err != nil {
		t.Fatalf("s.loadConfig() failed %v", err)
	}
	if _, ok := conf.Clients[clientName]; ok {
		t.Errorf("Clients[%s] should not exists in storage", clientName)
	}

	sec, err := s.loadSecrets(nil)
	if err != nil {
		t.Fatalf("s.loadSecrets() failed %v", err)
	}
	if _, ok := sec.ClientSecrets[test.TestClientID]; ok {
		t.Errorf("client secret should not exist in storage")
	}
}

func TestConfigClients_Delete_Error(t *testing.T) {
	s, cfg, _, h, iss, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientName := "test_client"

	tests := []struct {
		name       string
		persona    string
		clientName string
		status     int
	}{
		{
			name:       "client not exists",
			persona:    "admin",
			clientName: "invalid",
			status:     http.StatusNotFound,
		},
		{
			name:       "not admin",
			persona:    "non-admin",
			clientName: clientName,
			status:     http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h.Clear()

			resp := sendConfigClientsDelete(t, tc.persona, tc.clientName, test.TestClientID, test.TestClientSecret, s, iss)

			if resp.StatusCode != tc.status {
				t.Errorf("resp.StatusCode = %d, wants %d", resp.StatusCode, tc.status)
			}

			conf, err := s.loadConfig(nil, "test")
			if err != nil {
				t.Fatalf("s.loadConfig() failed %v", err)
			}
			if diff := cmp.Diff(cfg, conf, protocmp.Transform()); len(diff) != 0 {
				t.Errorf("config should not update, (-want, +got): %s", diff)
			}
		})
	}
}

func TestConfigClients_Delete_Hydra_Error(t *testing.T) {
	s, cfg, _, h, iss, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientName := "test_client"

	h.DeleteClientErr = &hydraapi.GenericError{Code: http.StatusServiceUnavailable}

	resp := sendConfigClientsDelete(t, "admin", clientName, test.TestClientID, test.TestClientSecret, s, iss)

	// TODO should use better http status.
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("resp.StatusCode = %d, wants %d", resp.StatusCode, http.StatusBadRequest)
	}

	conf, err := s.loadConfig(nil, "test")
	if err != nil {
		t.Fatalf("s.loadConfig() failed %v", err)
	}
	if diff := cmp.Diff(cfg, conf, protocmp.Transform()); len(diff) != 0 {
		t.Errorf("config should not update, (-want, +got): %s", diff)
	}
}

func TestConfigReset_Hydra(t *testing.T) {
	s, _, _, h, iss, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	cid := "c1"

	h.ListClientsResp = []*hydraapi.Client{
		{ClientID: cid},
	}

	h.CreateClientResp = &hydraapi.Client{
		ClientID: cid,
	}

	pname := "admin"
	var p *cpb.TestPersona
	if iss.Config() != nil {
		p = iss.Config().TestPersonas[pname]
	}

	tok, _, err := persona.NewAccessToken(pname, hydraPublicURL, test.TestClientID, noScope, p)
	if err != nil {
		t.Fatalf("persona.NewAccessToken(%q, %q, _, _) failed: %v", pname, hydraPublicURL, err)
	}

	q := url.Values{
		"client_id":     []string{test.TestClientID},
		"client_secret": []string{test.TestClientSecret},
	}
	path := strings.ReplaceAll(configResetPath, "{realm}", "test")
	header := http.Header{"Authorization": []string{"Bearer " + string(tok)}}
	resp := testhttp.SendTestRequest(t, s.Handler, http.MethodGet, path, q, nil, header)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("resp.StatusCode = %d, wants %d", resp.StatusCode, http.StatusOK)
	}

	if h.DeleteClientID != cid {
		t.Errorf("h.DeleteClientID = %s, wants %s", h.DeleteClientID, cid)
	}

	if h.CreateClientReq.Name != "test_client" && h.CreateClientReq.Name != "test_client2" {
		t.Errorf("h.CreateClientReq.Name = %s, wants test_client or test_client2", h.CreateClientReq.Name)
	}
}

func Test_HydraAccessTokenForEndpoint(t *testing.T) {
	store := storage.NewMemoryStorage("dam", "testdata/config")
	wh := clouds.NewMockTokenCreator(false)
	server, err := fakeoidcissuer.New(hydraPublicURL, &testkeys.PersonaBrokerKey, "dam", "testdata/config", false)
	if err != nil {
		t.Fatalf("fakeoidcissuer.New(%q, _, _) failed: %v", hydraPublicURL, err)
	}
	ctx := server.ContextWithClient(context.Background())
	s := NewService(&Options{
		Domain:         "test.org",
		DefaultBroker:  "no-broker",
		Store:          store,
		Warehouse:      wh,
		UseHydra:       useHydra,
		HydraAdminURL:  hydraAdminURL,
		HydraPublicURL: hydraPublicURL,
	})

	cfg, err := s.loadConfig(nil, "master")
	if err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}

	now := time.Now().Unix()
	identity := &ga4gh.Identity{
		Issuer:    hydraPublicURL,
		Subject:   "admin",
		IssuedAt:  now,
		Expiry:    now + 10000,
		Audiences: ga4gh.NewAudience(test.TestClientID),
		Extra: map[string]interface{}{
			"identities": []interface{}{"admin@faculty.example.edu"},
		},
	}

	tok, err := server.Sign(nil, identity)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	id, err := s.damSignedBearerTokenToPassportIdentity(ctx, cfg, tok, test.TestClientID)
	if err != nil {
		t.Fatalf("damSignedBearerTokenToPassportIdentity() failed: %v", err)
	}

	_, err = s.permissions.CheckAdmin(id)
	if err != nil {
		t.Errorf("CheckAdmin(%s) got error: %v", id.Subject, err)
	}
}
