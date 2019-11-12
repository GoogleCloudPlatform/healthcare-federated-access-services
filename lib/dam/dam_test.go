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
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/persona"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakeoidcissuer"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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
	s := NewService(ctx, "test.org", "no-broker", store, wh)
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
			Method: "PUT",
			Path:   "/dam/v1alpha/test/config/resources/new-resource",
			Input:  `{"item": $(GET /dam/v1alpha/test/config/resources/ga4gh-apis), "modification": {"testPersonas":{"dr_joe_elixir":{"access":["ga4gh-apis/beacon/discovery","ga4gh-apis/gcs_read/viewer","new-resource/beacon/discovery","new-resource/gcs_read/viewer"]}}}}`,
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
			Status: http.StatusFailedDependency,
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
			Status: http.StatusFailedDependency,
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
			Status: http.StatusFailedDependency,
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
	s := NewService(ctx, "test.org", "no-broker", store, nil)
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
	s := NewService(ctx, "test.org", "no-broker", store, nil)

	realm := "master"
	cfg, err := s.loadConfig(nil, realm)
	if err != nil {
		t.Fatalf("cannot load config, %v", err)
	}

	pname := "dr_joe_elixir"
	p := cfg.TestPersonas[pname]
	acTok, _, err := persona.NewAccessToken(pname, test.TestIssuerURL, test.TestClientID, p)
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
