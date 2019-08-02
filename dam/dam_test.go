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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/clouds"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/storage"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/test"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/validator"

	. "github.com/golang/mock/gomock"
)

func TestHandlers(t *testing.T) {
	store := storage.NewMemoryStorage("dam", "test/config")
	wh := clouds.NewMockTokenCreator(false)
	s := NewService(context.Background(), "test.org", store, wh)
	tests := []test.HandlerTest{
		{
			Method: "GET",
			Path:   "/dam",
			Output: `^{"name":"Data Access Manager","versions":\["v1alpha"\],"startTime":"[0-9]+","ui":{"description":"Test DAM","label":"Test DAM".*}}$`,
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
			Input:  `{"item": $(GET /dam/v1alpha/test/config/resources/ga4gh-apis), "modification": {"testPersonas":{"dr_joe_elixir":{"resources":{"ga4gh-apis":{"access":["beacon/discovery","gcs_read/viewer"]},"new-resource":{"access":["beacon/discovery","gcs_read/viewer"]}},"addResources":{"new-resource":{"access":["beacon/discovery","gcs_read/viewer"]}},"removeResources":{}}}}}`,
			Status: http.StatusOK,
		},
		{
			Method: "PATCH",
			Path:   "/dam/v1alpha/test/config/resources/new-resource",
			Input:  `{"item": {"ui":{"label":"foo","description":"bar"}}, "modification": {"testPersonas":{"dr_joe_elixir":{"resources":{"ga4gh-apis":{"access":["beacon/discovery","gcs_read/viewer"]}}}}}}`,
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
			Input:  `{"item":$(GET /dam/v1alpha/test/config/resources/ga4gh-apis/views/gcs_read), "modification": {"testPersonas":{"dr_joe_elixir":{"resources":{"ga4gh-apis":{"access":["beacon/discovery","gcs_read/viewer","gcs_read2/viewer"]}}}}}}`,
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
													"bucket": "ga4gh-apis-controlled-access"
												}
											}
										],
										"roles":{
											"viewer":{
												"policies":["bona_fide", "ethics", "GRU"]
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
												"policies":["bona_fide", "ethics", "GRU"]
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
			Output: `^.*"allow"`,
			Status: http.StatusOK,
		},
		{
			Method: "POST",
			Path:   "/dam/v1alpha/test/config/policies/new-policy",
			Input:  `{"item":{"allow":{"claim":"BonaFide","values":["https://test.org"]},"ui":{"label":"foo","description":"bar"}}}`,
			Output: ``,
			Status: http.StatusOK,
		},
		{
			Method: "PUT",
			Path:   "/dam/v1alpha/test/config/policies/new-policy",
			Input:  `{"item":{"allow":{"claim":"BonaFide","values":["https://test2.org"]},"ui":{"label":"foo","description":"bar"}}}`,
			Status: http.StatusOK,
		},
		{
			Method: "PATCH",
			Path:   "/dam/v1alpha/test/config/policies/new-policy",
			Input:  `{"item":{"allow":{"claim":"BonaFide","values":["https://test3.org"]},"ui":{"label":"foo","description":"bar"}}}`,
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
			Output: `^.*"idToken"`,
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
					"idToken": {
						"standardClaims": {
							"iss": "https://login.nih.gov/oidc/",
							"sub": "dr_joe@era.nih.gov",
							"picture": "https://pbs.twimg.com/profile_images/3443048571/ef5062acfce64a7aef1d75b4934fbee6_400x400.png"
						},
						"ga4ghClaims": [
							{
								"claimName": "AffiliationAndRole",
								"source": "https://example.edu",
								"value": "student@example.edu",
								"assertedDuration": "1d",
								"expiresDuration": "30d",
								"by": "so"
							},
							{
								"claimName": "ControlledAccessGrants",
								"source": "https://dbgap.nlm.nih.gov/aa",
								"value": "https://dac.nih.gov/datasets/phs000710",
								"assertedDuration": "1d",
								"expiresDuration": "30d",
								"by": "dac",
								"condition": {
									"AffiliationAndRole": {
										"value": ["faculty@example.edu"],
										"by": ["so"]
									}
								}
							}
						]
					},
					"resources": {
						"dataset_example" : {
							"access": ["bq_read/viewer", "gcs_read/viewer"]
						},
						"thousand-genomes" : {
							"access" : ["gcs-file-access/viewer"]
						}
					}
				}
			}`,
			Output: `^.*"dataset_example":\{\}`,
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
					"idToken": {
						"standardClaims": {
							"iss": "https://login.nih.gov/oidc/",
							"sub": "dr_joe@era.nih.gov",
							"picture": "https://pbs.twimg.com/profile_images/3443048571/ef5062acfce64a7aef1d75b4934fbee6_400x400.png"
						},
						"ga4ghClaims": [
							{
								"claimName": "AffiliationAndRole",
								"source": "https://example.edu",
								"value": "faculty@example.edu",
								"assertedDuration": "30d",
								"expiresDuration": "-1d",
								"by": "so"
							},
							{
								"claimName": "ControlledAccessGrants",
								"source": "https://dbgap.nlm.nih.gov/aa",
								"value": "https://dac.nih.gov/datasets/phs000710",
								"assertedDuration": "1d",
								"expiresDuration": "30d",
								"by": "dac",
								"condition": {
									"AffiliationAndRole": {
										"value": ["faculty@example.edu"],
										"by": ["so"]
									}
								}
							}
						]
					},
					"resources": {
						"dataset_example" : {
							"access": ["bq_read/viewer", "gcs_read/viewer"]
						},
						"thousand-genomes" : {
							"access" : ["gcs-file-access/viewer"]
						}
					}
				}
			}`,
			Output: `^.*"dataset_example":\{\}`,
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
					"idToken": {
						"standardClaims": {
							"iss": "https://login.elixir-czech.org/oidc/",
							"sub": "dr_joe@faculty.example.edu",
							"picture": "https://pbs.twimg.com/profile_images/497015367391121408/_cWXo-vA_400x400.jpeg"
						},
						"ga4ghClaims": [
							{
								"claimName": "BonaFide",
								"source": "https://example.edu",
								"value": "https://www.nature.com/articles/s41431-018-0219-y",
								"assertedDuration": "1d",
								"expiresDuration": "30d",
								"by": "peer"
							},
							{
								"claimName": "AcceptedTermsAndPolicies",
								"source": "https://example.edu",
								"value": "https://www.nature.com/articles/s41431-018-0219-y",
								"assertedDuration": "1d",
								"expiresDuration": "30d",
								"by": "self"
							}
						]
					},
					"resources": {
						"ga4gh-apis" : {
							"access" : ["beacon/discovery", "gcs_read/viewer"]
						}
					}
				}
			},`,
			Output: `^.*"ga4gh-apis":\{\}`,
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
			Output: `{"tokens":[]}`,
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
	test.HandlerTests(t, s.Handler, tests)
}

func TestMinConfig(t *testing.T) {
	store := storage.NewMemoryStorage("dam-min", "test/config")
	s := NewService(context.Background(), "test.org", store, nil)
	tests := []test.HandlerTest{
		{
			Name:    "restricted access of 'dr_joe_elixir' (which only exists in min config subdirectory)",
			Method:  "GET",
			Path:    "/dam/v1alpha/test/config/testPersonas/dr_joe_elixir",
			Persona: "admin",
			Status:  http.StatusOK,
		},
		{
			Name:    "bad persona name",
			Method:  "GET",
			Path:    "/dam/v1alpha/test/config/testPersonas/min_joes",
			Persona: "admin",
			Status:  http.StatusNotFound,
		},
	}
	for _, te := range tests {
		target := fmt.Sprintf("%s?persona=%s&client_id=%s&client_secret=%s", te.Path, te.Persona, test.TestClientID, test.TestClientSecret)
		var input io.Reader
		r := httptest.NewRequest(te.Method, target, input)
		w := httptest.NewRecorder()
		s.Handler.ServeHTTP(w, r)
		if w.Code != te.Status {
			t.Errorf("test %q returned wrong status code: got %d want %d", te.Name, w.Code, te.Status)
		}
	}
}

type contextMatcher struct{}

func (contextMatcher) Matches(x interface{}) bool {
	c, ok := x.(context.Context)
	if !ok {
		return false
	}
	requestTTLInNanoFloat64 := ga4gh.ContextKey("requested_ttl")
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
	store := storage.NewMemoryStorage("dam", "test/config")
	s := NewService(context.Background(), "test.org", store, nil)

	// Ensure pass context with TTL in validator
	var input io.Reader
	r := httptest.NewRequest("GET", "/dam/v1alpha/master/resources/ga4gh-apis/views/gcs_read/roles/viewer/token?persona=dr_joe_elixir", input)

	resName := "ga4gh-apis"
	viewName := "gcs_read"
	role := "viewer"
	realm := "master"
	ttl := time.Hour

	cfg, err := s.loadConfig(nil, realm)
	if err != nil {
		t.Fatalf("cannot load config, %v", err)
	}

	id, _, err := s.getPassportIdentity(cfg, nil, r)
	if err != nil {
		t.Fatalf("unable to obtain passport identity: %v", err)
	}

	ctrl := NewController(t)
	defer ctrl.Finish()

	mockValidator := validator.NewMockValidator(ctrl)
	mockValidator.EXPECT().Validate(contextMatcher{}, Any()).Return(true, nil).Times(3)

	policies := map[string]*validator.Policy{
		"bona_fide": {
			Allow: mockValidator,
		},
		"ethics": {
			Allow: mockValidator,
		},
		"GRU": {
			Allow: mockValidator,
		},
	}

	status, err := s.checkAuthorization(id, ttl, resName, viewName, role, cfg, getClientID(r), policies)
	if status != http.StatusOK || err != nil {
		t.Errorf("checkAuthorization(id, %v, %q, %q, %q, cfg, %q, policies) failed, expected %q, got %q: %v", ttl, resName, viewName, role, getClientID(r), http.StatusOK, status, err)
	}

	// TODO: we need more tests for other condition in checkAuthorization()
}
