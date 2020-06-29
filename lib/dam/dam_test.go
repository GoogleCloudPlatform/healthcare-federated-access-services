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
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"github.com/google/go-cmp/cmp/cmpopts" /* copybara-comment */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/coreos/go-oidc" /* copybara-comment */
	"github.com/go-openapi/strfmt" /* copybara-comment */
	"github.com/golang/protobuf/jsonpb" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */
	"bitbucket.org/creachadair/stringset" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/apis/hydraapi" /* copybara-comment: hydraapi */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/auditlog" /* copybara-comment: auditlog */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds" /* copybara-comment: clouds */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/errutil" /* copybara-comment: errutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/hydra" /* copybara-comment: hydra */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/kms/fakeencryption" /* copybara-comment: fakeencryption */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/kms/localsign" /* copybara-comment: localsign */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/persona" /* copybara-comment: persona */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/serviceinfo" /* copybara-comment: serviceinfo */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakehydra" /* copybara-comment: fakehydra */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakeoidcissuer" /* copybara-comment: fakeoidcissuer */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakesdl" /* copybara-comment: fakesdl */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/httptestclient" /* copybara-comment: httptestclient */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test" /* copybara-comment: test */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/testhttp" /* copybara-comment: testhttp */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/validator" /* copybara-comment: validator */

	lspb "google.golang.org/genproto/googleapis/logging/type" /* copybara-comment: log_severity_go_proto */
	lepb "google.golang.org/genproto/googleapis/logging/v2" /* copybara-comment: log_entry_go_proto */
	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
)

const (
	damURL           = "https://dam.example.com"
	hydraAdminURL    = "https://admin.hydra.example.com"
	hydraPublicURL   = "https://hydra.example.com/"
	hydraURLInternal = "https://hydra.internal.example.com/"
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
		ServiceName:    "dam",
		DefaultBroker:  "no-broker",
		Store:          store,
		Warehouse:      wh,
		UseHydra:       useHydra,
		HydraAdminURL:  hydraAdminURL,
		HydraPublicURL: hydraPublicURL,
		HydraSyncFreq:  time.Nanosecond,
		Encryption:     fakeencryption.New(),
	})
	tests := []test.HandlerTest{
		// Realm tests.
		{
			Method:  "GET",
			Path:    "/dam/v1alpha/master",
			Persona: "admin",
			Output:  `{}`,
			Status:  http.StatusOK,
		},
		{
			Method:  "POST",
			Path:    "/dam/v1alpha/test",
			Persona: "admin",
			Output:  `^.*exists`,
			// For now, all realms are marked as already in existence.
			Status: http.StatusConflict,
		},
		{
			Method:  "PUT",
			Path:    "/dam/v1alpha/test",
			Persona: "admin",
			Output:  ``,
			Status:  http.StatusOK,
		},
		{
			Method:  "PATCH",
			Path:    "/dam/v1alpha/test",
			Persona: "admin",
			Output:  ``,
			Status:  http.StatusOK,
		},
		{
			Method:  "DELETE",
			Path:    "/dam/v1alpha/test",
			Persona: "admin",
			Output:  ``,
			Status:  http.StatusOK,
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
			Method:  "GET",
			Path:    "/dam/v1alpha/master/processes",
			Persona: "admin",
			Output:  `^\{"processes":\{.*"gckeys"`,
			Status:  http.StatusOK,
		},
		{
			Method:  "POST",
			Path:    "/dam/v1alpha/master/processes",
			Persona: "admin",
			Output:  `^.*exists`,
			Status:  http.StatusConflict,
		},
		{
			Method:  "PUT",
			Path:    "/dam/v1alpha/master/processes",
			Persona: "admin",
			Output:  `^.*not allowed`,
			Status:  http.StatusBadRequest,
		},
		{
			Method:  "PATCH",
			Path:    "/dam/v1alpha/master/processes",
			Persona: "admin",
			Output:  `^.*not allowed`,
			Status:  http.StatusBadRequest,
		},
		{
			Method:  "DELETE",
			Path:    "/dam/v1alpha/master/processes",
			Persona: "admin",
			Output:  `^.*not allowed`,
			Status:  http.StatusBadRequest,
		},
		{
			Method:  "GET",
			Path:    "/dam/v1alpha/master/processes/gckeys",
			Persona: "admin",
			Output:  `^\{"process":\{.*"processName":"gckeys"`,
			Status:  http.StatusOK,
		},
		{
			Method:  "POST",
			Path:    "/dam/v1alpha/master/processes/gckeys",
			Persona: "admin",
			Output:  `^.*exists`,
			Status:  http.StatusConflict,
		},
		{
			Method:  "PUT",
			Path:    "/dam/v1alpha/master/processes/gckeys",
			Persona: "admin",
			Output:  `^.*not allowed`,
			Status:  http.StatusBadRequest,
		},
		{
			Method:  "PATCH",
			Path:    "/dam/v1alpha/master/processes/gckeys",
			Persona: "admin",
			Output:  `^.*not allowed`,
			Status:  http.StatusBadRequest,
		},
		{
			Method:  "DELETE",
			Path:    "/dam/v1alpha/master/processes/gckeys",
			Persona: "admin",
			Output:  `^.*not allowed`,
			Status:  http.StatusBadRequest,
		},
		{
			Method:  "GET",
			Path:    "/dam/v1alpha/master/config",
			Persona: "admin",
			Output:  `^.*dr_joe.*$`,
			Status:  http.StatusOK,
		},
		{
			Method:  "POST",
			Path:    "/dam/v1alpha/master/config",
			Persona: "admin",
			Input:   `{}`,
			Output:  `^.*exists`,
			Status:  http.StatusConflict,
		},
		{
			Method:  "PUT",
			Path:    "/dam/v1alpha/master/config",
			Persona: "admin",
			Input:   `{"item":{"version":"v100"}}`,
			Output:  `^.*version`,
			Status:  http.StatusBadRequest,
		},
		{
			Method:  "PUT",
			Path:    "/dam/v1alpha/test/config",
			Persona: "admin",
			Input:   `{"item": $(GET /dam/v1alpha/master/config)}`,
			Output:  ``,
			Status:  http.StatusOK,
		},
		{
			Method:  "GET",
			Path:    "/dam/v1alpha/test/config/options",
			Persona: "admin",
			Output:  `^.*readOnlyMasterRealm.*"descriptors".*readOnlyMasterRealm`,
			Status:  http.StatusOK,
		},
		{
			Method:  "POST",
			Path:    "/dam/v1alpha/test/config/options",
			Persona: "admin",
			Input:   `{}`,
			Output:  `^.*exists`,
			Status:  http.StatusConflict,
		},
		{
			Method:  "PUT",
			Path:    "/dam/v1alpha/test/config/options",
			Persona: "admin",
			Input:   `{"item": $(GET /dam/v1alpha/test/config/options)}`,
			Status:  http.StatusOK,
		},
		{
			Method:  "PATCH",
			Path:    "/dam/v1alpha/test/config/options",
			Persona: "admin",
			Input:   `{"item": {"gcpServiceAccountProject": "patch-options-project"}}`,
			Status:  http.StatusOK,
		},
		{
			Method:  "DELETE",
			Path:    "/dam/v1alpha/test/config/options",
			Persona: "admin",
			Output:  `^.*DELETE not allowed`,
			Status:  http.StatusBadRequest,
		},
		{
			Method:  "GET",
			Path:    "/dam/v1alpha/test/config/resources/ga4gh-apis",
			Persona: "admin",
			Output:  `^.*"views"`,
			Status:  http.StatusOK,
		},
		{
			Method:  "POST",
			Path:    "/dam/v1alpha/test/config/resources/new-resource",
			Persona: "admin",
			Input:   `{"item":{"maxTokenTtl": "3h","ui":{"label":"label","description":"desc"}}}`,
			Output:  ``,
			Status:  http.StatusOK,
		},
		{
			Name:    "PUT /dam/v1alpha/test/config/resources/new-resource (unordered access list)",
			Persona: "admin",
			Method:  "PUT",
			Path:    "/dam/v1alpha/test/config/resources/new-resource",
			Input:   `{"item": $(GET /dam/v1alpha/test/config/resources/ga4gh-apis), "modification": {"testPersonas":{"dr_joe_elixir":{"access":["ga4gh-apis/gcs_read/viewer","ga4gh-apis/beacon/discovery","new-resource/beacon/discovery","new-resource/gcs_read/viewer"]}}}}`,
			Status:  http.StatusOK,
		},
		{
			Method:  "PATCH",
			Path:    "/dam/v1alpha/test/config/resources/new-resource",
			Persona: "admin",
			Input:   `{"item": {"ui":{"label":"foo","description":"bar"}}, "modification": {"testPersonas":{"dr_joe_elixir":{"access":["ga4gh-apis/beacon/discovery","ga4gh-apis/gcs_read/viewer"]}}}}`,
			Status:  http.StatusOK,
		},
		{
			Method:  "DELETE",
			Path:    "/dam/v1alpha/test/config/resources/new-resource",
			Persona: "admin",
			Output:  ``,
			Status:  http.StatusOK,
		},
		{
			Method:  "GET",
			Path:    "/dam/v1alpha/test/config/resources/ga4gh-apis/views/gcs_read",
			Persona: "admin",
			Output:  `^.*"serviceTemplate"`,
			Status:  http.StatusOK,
		},
		{
			Method:  "POST",
			Path:    "/dam/v1alpha/test/config/resources/ga4gh-apis/views/gcs_read2",
			Persona: "admin",
			Input:   `{"item":$(GET /dam/v1alpha/test/config/resources/ga4gh-apis/views/gcs_read), "modification": {"testPersonas":{"dr_joe_elixir":{"access":["ga4gh-apis/beacon/discovery","ga4gh-apis/gcs_read/viewer","ga4gh-apis/gcs_read2/viewer"]}}}}`,
			Output:  ``,
			Status:  http.StatusOK,
		},
		{
			Method:  "PUT",
			Path:    "/dam/v1alpha/test/config/resources/ga4gh-apis/views/gcs_read2",
			Persona: "admin",
			Input: `{
									"item": {
										"serviceTemplate":"gcs",
										"labels": {
										  "version":"Phase 3"
										},
										"items": [
											{
												"args": {
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
			Output: `*"code":3,*resources/ga4gh-apis/views/gcs_read2/items/0/vars/bad-var-name*`,
			Status: http.StatusBadRequest,
		},
		{
			Method:  "PUT",
			Path:    "/dam/v1alpha/test/config/resources/ga4gh-apis/views/gcs_read2",
			Persona: "admin",
			Input: `{
									"item": {
										"serviceTemplate":"gcs",
										"labels": {
											"version":"Phase 3"
										},
										"items": [
											{
												"args": {
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
			Method:  "PATCH",
			Path:    "/dam/v1alpha/test/config/resources/ga4gh-apis/views/gcs_read2",
			Persona: "admin",
			Input: `{
									"item": {
									  "labels": {
										  "version": "v4"
										},
										"items": [
											{
												"args": {
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
			Method:  "DELETE",
			Path:    "/dam/v1alpha/test/config/resources/ga4gh-apis/views/gcs_read2",
			Persona: "admin",
			Output:  ``,
			Status:  http.StatusOK,
		},
		{
			Method:  "GET",
			Path:    "/dam/v1alpha/test/config/trustedIssuers/elixir",
			Persona: "admin",
			Output:  `^.*"issuer"`,
			Status:  http.StatusOK,
		},
		{
			Method:  "POST",
			Path:    "/dam/v1alpha/test/config/trustedIssuers/new-issuer",
			Persona: "admin",
			Input:   `{"item":{"issuer":"https://test.org","ui":{"label":"foo","description":"bar"}}}`,
			Output:  ``,
			Status:  http.StatusOK,
		},
		{
			Method:  "PUT",
			Path:    "/dam/v1alpha/test/config/trustedIssuers/new-issuer",
			Persona: "admin",
			Input:   `{"item":{"issuer":"https://test.org","ui":{"label":"foo","description":"bar"}}}`,
			Status:  http.StatusOK,
		},
		{
			Method:  "PATCH",
			Path:    "/dam/v1alpha/test/config/trustedIssuers/new-issuer",
			Persona: "admin",
			Input:   `{"item":{"issuer":"https://test2.org","ui":{"label":"foo","description":"bar"}}}`,
			Status:  http.StatusOK,
		},
		{
			Method:  "DELETE",
			Path:    "/dam/v1alpha/test/config/trustedIssuers/new-issuer",
			Persona: "admin",
			Output:  ``,
			Status:  http.StatusOK,
		},
		{
			Method:  "GET",
			Path:    "/dam/v1alpha/test/config/trustedSources/elixir_institutes",
			Persona: "admin",
			Output:  `^.*"sources"`,
			Status:  http.StatusOK,
		},
		{
			Method:  "POST",
			Path:    "/dam/v1alpha/test/config/trustedSources/new-source",
			Persona: "admin",
			Input:   `{"item":{"sources":["https://test.org"],"ui":{"label":"foo","description":"bar"}}}`,
			Output:  ``,
			Status:  http.StatusOK,
		},
		{
			Method:  "PUT",
			Path:    "/dam/v1alpha/test/config/trustedSources/new-source",
			Persona: "admin",
			Input:   `{"item":{"sources":["https://test2.org"],"ui":{"label":"foo","description":"bar"}}}`,
			Status:  http.StatusOK,
		},
		{
			Method:  "PATCH",
			Path:    "/dam/v1alpha/test/config/trustedSources/new-source",
			Persona: "admin",
			Input:   `{"item":{"sources":["https://test3.org"],"ui":{"label":"foo","description":"bar"}}}`,
			Status:  http.StatusOK,
		},
		{
			Method:  "DELETE",
			Path:    "/dam/v1alpha/test/config/trustedSources/new-source",
			Persona: "admin",
			Output:  ``,
			Status:  http.StatusOK,
		},
		{
			Method:  "GET",
			Path:    "/dam/v1alpha/test/config/policies/bona_fide",
			Persona: "admin",
			Output:  `^.*"anyOf"`,
			Status:  http.StatusOK,
		},
		{
			Method:  "POST",
			Path:    "/dam/v1alpha/test/config/policies/new-policy",
			Persona: "admin",
			Input:   `{"item":{"anyOf":[{"allOf":[{"type":"ResearcherStatus","value":"const:https://test.org"}]}],"ui":{"label":"foo","description":"bar"}}}`,
			Output:  ``,
			Status:  http.StatusOK,
		},
		{
			Method:  "PUT",
			Path:    "/dam/v1alpha/test/config/policies/new-policy",
			Persona: "admin",
			Input:   `{"item":{"anyOf":[{"allOf":[{"type":"ResearcherStatus","value":"const:https://test2.org"}]}],"ui":{"label":"foo","description":"bar"}}}`,
			Status:  http.StatusOK,
		},
		{
			Method:  "PATCH",
			Path:    "/dam/v1alpha/test/config/policies/new-policy",
			Persona: "admin",
			Input:   `{"item":{"anyOf":[{"allOf":[{"type":"ResearcherStatus","value":"const:https://test3.org"}]}],"ui":{"label":"foo","description":"bar"}}}`,
			Status:  http.StatusOK,
		},
		{
			Method:  "DELETE",
			Path:    "/dam/v1alpha/test/config/policies/new-policy",
			Persona: "admin",
			Output:  ``,
			Status:  http.StatusOK,
		},
		{
			Method:  "DELETE",
			Path:    "/dam/v1alpha/test/config/policies/whitelist",
			Persona: "admin",
			Output:  `*built-in policy*`,
			Status:  http.StatusBadRequest,
		},
		{
			Method:  "GET",
			Path:    "/dam/v1alpha/test/config/visaTypes/ResearcherStatus",
			Persona: "admin",
			Output:  `^.*"ui"`,
			Status:  http.StatusOK,
		},
		{
			Method:  "POST",
			Path:    "/dam/v1alpha/test/config/visaTypes/new.claim",
			Persona: "admin",
			Input:   `{"item":{"ui":{"label":"new.Claim","description":"bar"}}}`,
			Output:  ``,
			Status:  http.StatusOK,
		},
		{
			Method:  "PUT",
			Path:    "/dam/v1alpha/test/config/visaTypes/new.claim",
			Persona: "admin",
			Input:   `{"item":{"ui":{"label":"new.Claim2","description":"bar"}}}`,
			Status:  http.StatusOK,
		},
		{
			Method:  "PATCH",
			Path:    "/dam/v1alpha/test/config/visaTypes/new.claim",
			Persona: "admin",
			Input:   `{"item":{"ui":{"label":"new.Claim3","description":"bar"}}}`,
			Status:  http.StatusOK,
		},
		{
			Method:  "DELETE",
			Path:    "/dam/v1alpha/test/config/visaTypes/new.claim",
			Persona: "admin",
			Output:  ``,
			Status:  http.StatusOK,
		},
		{
			Method:  "GET",
			Path:    "/dam/v1alpha/test/config/serviceTemplates/gcs",
			Persona: "admin",
			Output:  `*"serviceName":"gcs"*`,
			Status:  http.StatusOK,
		},
		{
			Method:  "POST",
			Path:    "/dam/v1alpha/test/config/serviceTemplates/new-service",
			Persona: "admin",
			Input:   `{"item":$(GET /dam/v1alpha/test/config/serviceTemplates/gcs)}`,
			Output:  ``,
			Status:  http.StatusOK,
		},
		{
			Method:  "PUT",
			Path:    "/dam/v1alpha/test/config/serviceTemplates/new-service",
			Persona: "admin",
			Input:   `{"item":$(GET /dam/v1alpha/test/config/serviceTemplates/gcs)}`,
			Status:  http.StatusOK,
		},
		{
			Method:  "PATCH",
			Path:    "/dam/v1alpha/test/config/serviceTemplates/new-service",
			Persona: "admin",
			Input: `{"item":{"interfaces":{"gcp:gs":"gs://${bucket}"},"ui":{"label":"foo","description":"bar"}, "roles": {
        "viewer": {
				  "serviceArgs": {
					  "roles": {"values": ["roles/storage.objectViewer"]}
					},
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
			Method:  "DELETE",
			Path:    "/dam/v1alpha/test/config/serviceTemplates/new-service",
			Persona: "admin",
			Output:  ``,
			Status:  http.StatusOK,
		},
		{
			Method:  "GET",
			Path:    "/dam/v1alpha/test/config/testPersonas/dr_joe_elixir",
			Persona: "admin",
			Output:  `^.*"passport"`,
			Status:  http.StatusOK,
		},
		{
			Method:  "POST",
			Path:    "/dam/v1alpha/test/config/testPersonas/new-persona",
			Persona: "admin",
			Input:   `{"item":$(GET /dam/v1alpha/test/config/testPersonas/dr_joe_elixir)}`,
			Output:  ``,
			Status:  http.StatusOK,
		},
		{
			Method:  "PUT",
			Path:    "/dam/v1alpha/test/config/testPersonas/new-persona",
			Persona: "admin",
			Input:   `{"item":$(GET /dam/v1alpha/test/config/testPersonas/dr_joe_elixir)}`,
			Status:  http.StatusOK,
		},
		{
			Method:  "PATCH",
			Path:    "/dam/v1alpha/test/config/testPersonas/new-persona",
			Persona: "admin",
			Input:   `{"item":$(GET /dam/v1alpha/test/config/testPersonas/dr_joe_elixir)}`,
			Status:  http.StatusOK,
		},
		{
			Method:  "DELETE",
			Path:    "/dam/v1alpha/test/config/testPersonas/new-persona",
			Persona: "admin",
			Output:  ``,
			Status:  http.StatusOK,
		},
		{
			Name:    "Claim condition dependency check (student vs. faculty)",
			Method:  "PATCH",
			Path:    "/dam/v1alpha/test/config/testPersonas/dr_joe_era_commons",
			Persona: "admin",
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
			Name:    "Claim condition dependency expired",
			Method:  "PATCH",
			Path:    "/dam/v1alpha/test/config/testPersonas/dr_joe_era_commons",
			Persona: "admin",
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
			Name:    "BonaFide claim expiry check",
			Method:  "POST",
			Path:    "/dam/v1alpha/test/config/testPersonas/expired-persona",
			Persona: "admin",
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
								"type": "ResearcherStatus",
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
			Method:  "PUT",
			Path:    "/dam/v1alpha/master/clients:sync",
			Persona: "non-admin",
			Output:  `^.*not allowed`,
			Status:  http.StatusBadRequest,
		},
		{
			Method:       "PUT",
			Path:         "/dam/v1alpha/master/clients:sync",
			Persona:      "non-admin",
			ClientID:     "bad",
			ClientSecret: "worse",
			Output:       `^.*unrecognized`,
			Status:       http.StatusUnauthorized,
		},
		{
			Method:  "PATCH",
			Path:    "/dam/v1alpha/master/clients:sync",
			Persona: "non-admin",
			Output:  `^.*not allowed`,
			Status:  http.StatusBadRequest,
		},
		{
			Method:  "DELETE",
			Path:    "/dam/v1alpha/master/clients:sync",
			Persona: "non-admin",
			Output:  `^.*not allowed`,
			Status:  http.StatusBadRequest,
		},
		{
			Method:  "GET",
			Path:    "/dam/v1alpha/test/clients:sync",
			Persona: "admin",
			Output:  `^.*client sync only allow on master realm`,
			Status:  http.StatusForbidden,
		},
		{
			Method:  "POST",
			Path:    "/dam/v1alpha/test/clients:sync",
			Persona: "admin",
			Output:  `^.*client sync only allow on master realm`,
			Status:  http.StatusForbidden,
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
	opts := &Options{
		HTTPClient:       server.Client(),
		Domain:           "test.org",
		ServiceName:      "dam",
		DefaultBroker:    "no-broker",
		Store:            store,
		Warehouse:        nil,
		UseHydra:         useHydra,
		HydraAdminURL:    hydraAdminURL,
		HydraPublicURL:   hydraPublicURL,
		HidePolicyBasis:  true,
		HideRejectDetail: true,
		Encryption:       fakeencryption.New(),
	}
	s := NewService(opts)
	verifyService(t, s.domainURL, opts.Domain, "domainURL")
	verifyService(t, s.defaultBroker, opts.DefaultBroker, "defaultBroker")
	verifyService(t, s.serviceName, opts.ServiceName, "serviceName")
	verifyService(t, strconv.FormatBool(s.useHydra), strconv.FormatBool(opts.UseHydra), "useHydra")
	verifyService(t, s.hydraAdminURL, opts.HydraAdminURL, "hydraAdminURL")
	verifyService(t, s.hydraPublicURL, opts.HydraPublicURL, "hydraPublicURL")
	verifyServiceBool(t, s.hidePolicyBasis, opts.HidePolicyBasis, "hidePolicyBasis")
	verifyServiceBool(t, s.hideRejectDetail, opts.HideRejectDetail, "hideRejectDetail")

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

func TestConfig_Add_NilResource(t *testing.T) {
	store := storage.NewMemoryStorage("dam", "testdata/config")
	wh := clouds.NewMockTokenCreator(false)
	broker, err := persona.NewBroker(hydraPublicURL, &testkeys.PersonaBrokerKey, "dam", "testdata/config", false)
	if err != nil {
		t.Fatalf("NewBroker() failed: %v", err)
	}
	s := NewService(&Options{
		HTTPClient:     httptestclient.New(broker.Handler),
		Domain:         "test.org",
		ServiceName:    "dam",
		DefaultBroker:  testBroker,
		Store:          store,
		Warehouse:      wh,
		UseHydra:       useHydra,
		HydraAdminURL:  hydraAdminURL,
		HydraPublicURL: hydraPublicURL,
		HydraSyncFreq:  time.Nanosecond,
		Encryption:     fakeencryption.New(),
	})

	cfg, err := s.loadConfig(nil, storage.DefaultRealm)
	if err != nil {
		t.Fatalf("load config failed: %v", err)
	}

	copy := proto.Clone(cfg).(*pb.DamConfig)
	copy.Resources = nil
	copy.TestPersonas = nil

	// Store invalid config to storage
	if err := s.store.Write(storage.ConfigDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, copy, nil); err != nil {
		t.Fatalf("Write config failed: %v", err)
	}

	req := &pb.ConfigResourceRequest{Item: cfg.Resources["dataset_example"]}

	resp := damSendTestRequest(t, http.MethodPost, configResourcePath, "dataset_example", "test", "admin", test.TestClientID, test.TestClientSecret, req, s, broker)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Status = %d, wants %d", resp.StatusCode, http.StatusOK)
	}
}

func verifyService(t *testing.T, got, want, field string) {
	t.Helper()
	if got != want {
		t.Errorf("service %q mismatch: got %q, want %q", field, got, want)
	}
}

func verifyServiceBool(t *testing.T, got, want bool, field string) {
	t.Helper()
	if got != want {
		t.Errorf("service %q mismatch: got %v, want %v", field, got, want)
	}
}

type contextMatcher struct{}

func (contextMatcher) Matches(x interface{}) bool {
	c, ok := x.(context.Context)
	if !ok {
		return false
	}
	_, ok = c.Value(validator.RequestTTLInNanoFloat64).(float64)
	if !ok {
		return false
	}
	return true
}

func (contextMatcher) String() string {
	return "context has requested_ttl"
}

type authTestContext struct {
	dam      *Service
	ctx      context.Context
	id       *ga4gh.Identity
	ttl      time.Duration
	cfg      *pb.DamConfig
	resource string
	view     string
	role     string
}

func setupAuthorizationTest(t *testing.T) *authTestContext {
	t.Helper()

	store := storage.NewMemoryStorage("dam", "testdata/config")
	server, err := fakeoidcissuer.New(hydraPublicURL, &testkeys.PersonaBrokerKey, "dam", "testdata/config", false)
	if err != nil {
		t.Fatalf("fakeoidcissuer.New(%q, _, _) failed: %v", hydraPublicURL, err)
	}
	ctx := server.ContextWithClient(context.Background())
	s := NewService(&Options{
		HTTPClient:     server.Client(),
		Domain:         "test.org",
		ServiceName:    "dam",
		DefaultBroker:  "no-broker",
		Store:          store,
		Warehouse:      nil,
		UseHydra:       useHydra,
		HydraAdminURL:  hydraAdminURL,
		HydraPublicURL: hydraPublicURL,
		Encryption:     fakeencryption.New(),
	})

	cfg, err := s.loadConfig(nil, storage.DefaultRealm)
	if err != nil {
		t.Fatalf("cannot load config, %v", err)
	}

	pname := "dr_joe_elixir"
	p := cfg.TestPersonas[pname]
	acTok, _, err := persona.NewAccessToken(pname, hydraPublicURL, test.TestClientID, persona.DefaultScope, p)
	if err != nil {
		t.Fatalf("persona.NewAccessToken(%q, %q, _, _) failed: %v", pname, hydraPublicURL, err)
	}

	id, err := s.upstreamTokenToPassportIdentity(ctx, cfg, nil, string(acTok), test.TestClientID)
	if err != nil {
		t.Fatalf("unable to obtain passport identity: %v", err)
	}

	return &authTestContext{
		dam:      s,
		ctx:      ctx,
		id:       id,
		ttl:      time.Hour,
		cfg:      cfg,
		resource: "ga4gh-apis",
		view:     "gcs_read",
		role:     "viewer",
	}
}

func TestCheckAuthorization(t *testing.T) {
	auth := setupAuthorizationTest(t)
	err := checkAuthorization(auth.ctx, auth.id, auth.ttl, auth.resource, auth.view, auth.role, auth.cfg, test.TestClientID, auth.dam.ValidateCfgOpts(storage.DefaultRealm, nil))
	if err != nil {
		t.Errorf("checkAuthorization(ctx, id, %v, %q, %q, %q, cfg, %q) failed, expected %d, got: %v", auth.ttl, auth.resource, auth.view, auth.role, test.TestClientID, http.StatusOK, err)
	}

	// TODO: we need more tests for other condition in checkAuthorization()
}

func TestCheckAuthorization_UntrustedIssuer(t *testing.T) {
	// Perform exactly the same call as TestCheckAuthorization() except remove trust of the visa issuer string
	auth := setupAuthorizationTest(t)
	delete(auth.cfg.TrustedIssuers, "test")
	delete(auth.cfg.TrustedIssuers, "testBroker")

	id, err := auth.dam.populateIdentityVisas(auth.ctx, auth.id, auth.cfg)
	if err != nil {
		t.Fatalf("unable to obtain passport identity: %v", err)
	}

	err = checkAuthorization(auth.ctx, id, auth.ttl, auth.resource, auth.view, auth.role, auth.cfg, test.TestClientID, auth.dam.ValidateCfgOpts(storage.DefaultRealm, nil))
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("checkAuthorization(ctx, id, %v, %q, %q, %q, cfg, %q) failed, expected %d, got: %v", auth.ttl, auth.resource, auth.view, auth.role, test.TestClientID, codes.PermissionDenied, err)
	}
	if errutil.ErrorReason(err) != errUntrustedIssuer {
		t.Errorf("errutil.ErrorReason() = %s want %s", errutil.ErrorReason(err), errUntrustedIssuer)
	}
}

func TestCheckAuthorization_ResourceNotFound(t *testing.T) {
	auth := setupAuthorizationTest(t)
	auth.cfg.Resources = nil

	id, err := auth.dam.populateIdentityVisas(auth.ctx, auth.id, auth.cfg)
	if err != nil {
		t.Fatalf("unable to obtain passport identity: %v", err)
	}

	err = checkAuthorization(auth.ctx, id, auth.ttl, auth.resource, auth.view, auth.role, auth.cfg, test.TestClientID, auth.dam.ValidateCfgOpts(storage.DefaultRealm, nil))
	if status.Code(err) != codes.NotFound {
		t.Errorf("checkAuthorization(ctx, id, %v, %q, %q, %q, cfg, %q) failed, expected %d, got: %v", auth.ttl, auth.resource, auth.view, auth.role, test.TestClientID, codes.NotFound, err)
	}
	if errutil.ErrorReason(err) != errResourceNotFoound {
		t.Errorf("errutil.ErrorReason() = %s want %s", errutil.ErrorReason(err), errResourceNotFoound)
	}
}

func TestCheckAuthorization_ResourceViewNotFoound(t *testing.T) {
	auth := setupAuthorizationTest(t)
	auth.cfg.Resources[auth.resource].Views = nil

	id, err := auth.dam.populateIdentityVisas(auth.ctx, auth.id, auth.cfg)
	if err != nil {
		t.Fatalf("unable to obtain passport identity: %v", err)
	}

	err = checkAuthorization(auth.ctx, id, auth.ttl, auth.resource, auth.view, auth.role, auth.cfg, test.TestClientID, auth.dam.ValidateCfgOpts(storage.DefaultRealm, nil))
	if status.Code(err) != codes.NotFound {
		t.Errorf("checkAuthorization(ctx, id, %v, %q, %q, %q, cfg, %q) failed, expected %d, got: %v", auth.ttl, auth.resource, auth.view, auth.role, test.TestClientID, codes.NotFound, err)
	}
	if errutil.ErrorReason(err) != errResourceViewNotFoound {
		t.Errorf("errutil.ErrorReason() = %s want %s", errutil.ErrorReason(err), errResourceViewNotFoound)
	}
}

func TestCheckAuthorization_ResolveAggregatesFail(t *testing.T) {
	auth := setupAuthorizationTest(t)
	auth.cfg.ServiceTemplates = nil

	id, err := auth.dam.populateIdentityVisas(auth.ctx, auth.id, auth.cfg)
	if err != nil {
		t.Fatalf("unable to obtain passport identity: %v", err)
	}

	err = checkAuthorization(auth.ctx, id, auth.ttl, auth.resource, auth.view, auth.role, auth.cfg, test.TestClientID, auth.dam.ValidateCfgOpts(storage.DefaultRealm, nil))
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("checkAuthorization(ctx, id, %v, %q, %q, %q, cfg, %q) failed, expected %d, got: %v", auth.ttl, auth.resource, auth.view, auth.role, test.TestClientID, codes.PermissionDenied, err)
	}
	if errutil.ErrorReason(err) != errResolveAggregatesFail {
		t.Errorf("errutil.ErrorReason() = %s want %s", errutil.ErrorReason(err), errResolveAggregatesFail)
	}
}

func TestCheckAuthorization_RoleNotAvailable(t *testing.T) {
	auth := setupAuthorizationTest(t)
	auth.role = "invalid"

	id, err := auth.dam.populateIdentityVisas(auth.ctx, auth.id, auth.cfg)
	if err != nil {
		t.Fatalf("unable to obtain passport identity: %v", err)
	}

	err = checkAuthorization(auth.ctx, id, auth.ttl, auth.resource, auth.view, auth.role, auth.cfg, test.TestClientID, auth.dam.ValidateCfgOpts(storage.DefaultRealm, nil))
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("checkAuthorization(ctx, id, %v, %q, %q, %q, cfg, %q) failed, expected %d, got: %v", auth.ttl, auth.resource, auth.view, auth.role, test.TestClientID, codes.PermissionDenied, err)
	}
	if errutil.ErrorReason(err) != errRoleNotAvailable {
		t.Errorf("errutil.ErrorReason() = %s want %s", errutil.ErrorReason(err), errRoleNotAvailable)
	}
}

func TestCheckAuthorization_CannotResolveServiceRole(t *testing.T) {
	auth := setupAuthorizationTest(t)
	auth.cfg.ServiceTemplates["gcs"].ServiceRoles = nil

	id, err := auth.dam.populateIdentityVisas(auth.ctx, auth.id, auth.cfg)
	if err != nil {
		t.Fatalf("unable to obtain passport identity: %v", err)
	}

	err = checkAuthorization(auth.ctx, id, auth.ttl, auth.resource, auth.view, auth.role, auth.cfg, test.TestClientID, auth.dam.ValidateCfgOpts(storage.DefaultRealm, nil))
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("checkAuthorization(ctx, id, %v, %q, %q, %q, cfg, %q) failed, expected %d, got: %v", auth.ttl, auth.resource, auth.view, auth.role, test.TestClientID, codes.PermissionDenied, err)
	}
	if errutil.ErrorReason(err) != errCannotResolveServiceRole {
		t.Errorf("errutil.ErrorReason() = %s want %s", errutil.ErrorReason(err), errCannotResolveServiceRole)
	}
}

func TestCheckAuthorization_NoPolicyDefined(t *testing.T) {
	auth := setupAuthorizationTest(t)
	auth.cfg.Resources[auth.resource].Views[auth.view].Roles[auth.role].Policies = nil

	id, err := auth.dam.populateIdentityVisas(auth.ctx, auth.id, auth.cfg)
	if err != nil {
		t.Fatalf("unable to obtain passport identity: %v", err)
	}

	err = checkAuthorization(auth.ctx, id, auth.ttl, auth.resource, auth.view, auth.role, auth.cfg, test.TestClientID, auth.dam.ValidateCfgOpts(storage.DefaultRealm, nil))
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("checkAuthorization(ctx, id, %v, %q, %q, %q, cfg, %q) failed, expected %d, got: %v", auth.ttl, auth.resource, auth.view, auth.role, test.TestClientID, codes.PermissionDenied, err)
	}
	if errutil.ErrorReason(err) != errNoPolicyDefined {
		t.Errorf("errutil.ErrorReason() = %s want %s", errutil.ErrorReason(err), errNoPolicyDefined)
	}
}

func TestCheckAuthorization_CannotEnforcePolicies(t *testing.T) {
	auth := setupAuthorizationTest(t)
	auth.resource = "dataset_example"
	auth.cfg.Policies["dac"].AnyOf[0].AllOf[0].Value = "const:https://dac.nih.gov/datasets/${NOT_DATASET}"

	id, err := auth.dam.populateIdentityVisas(auth.ctx, auth.id, auth.cfg)
	if err != nil {
		t.Fatalf("unable to obtain passport identity: %v", err)
	}

	err = checkAuthorization(auth.ctx, id, auth.ttl, auth.resource, auth.view, auth.role, auth.cfg, test.TestClientID, auth.dam.ValidateCfgOpts(storage.DefaultRealm, nil))
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("checkAuthorization(ctx, id, %v, %q, %q, %q, cfg, %q) failed, expected %d, got: %v", auth.ttl, auth.resource, auth.view, auth.role, test.TestClientID, codes.PermissionDenied, err)
	}
	if errutil.ErrorReason(err) != errCannotEnforcePolicies {
		t.Errorf("errutil.ErrorReason() = %s want %s", errutil.ErrorReason(err), errCannotEnforcePolicies)
	}
}

func TestCheckAuthorization_RejectedPolicy(t *testing.T) {
	auth := setupAuthorizationTest(t)
	auth.resource = "dataset_example"

	id, err := auth.dam.populateIdentityVisas(auth.ctx, auth.id, auth.cfg)
	if err != nil {
		t.Fatalf("unable to obtain passport identity: %v", err)
	}

	err = checkAuthorization(auth.ctx, id, auth.ttl, auth.resource, auth.view, auth.role, auth.cfg, test.TestClientID, auth.dam.ValidateCfgOpts(storage.DefaultRealm, nil))
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("checkAuthorization(ctx, id, %v, %q, %q, %q, cfg, %q) failed, expected %d, got: %v", auth.ttl, auth.resource, auth.view, auth.role, test.TestClientID, codes.PermissionDenied, err)
	}
	if errutil.ErrorReason(err) != errRejectedPolicy {
		t.Errorf("errutil.ErrorReason() = %s want %s", errutil.ErrorReason(err), errRejectedPolicy)
	}
}

func TestCheckAuthorization_Whitelist(t *testing.T) {
	auth := setupAuthorizationTest(t)
	auth.resource = "dataset_example"

	id, err := auth.dam.populateIdentityVisas(auth.ctx, auth.id, auth.cfg)
	if err != nil {
		t.Fatalf("unable to obtain passport identity: %v", err)
	}

	// Establish rejection due to not meeting policy.
	err = checkAuthorization(auth.ctx, id, auth.ttl, auth.resource, auth.view, auth.role, auth.cfg, test.TestClientID, auth.dam.ValidateCfgOpts(storage.DefaultRealm, nil))
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("setup checkAuthorization(ctx, id, %v, %q, %q, %q, cfg, %q) failed, expected %d, got: %v", auth.ttl, auth.resource, auth.view, auth.role, test.TestClientID, codes.PermissionDenied, err)
	}
	if errutil.ErrorReason(err) != errRejectedPolicy {
		t.Errorf("setup errutil.ErrorReason() = %s want %s", errutil.ErrorReason(err), errRejectedPolicy)
	}

	// Now try again with being on the whitelist.
	auth.cfg.Resources[auth.resource].Views[auth.view].Roles[auth.role].Policies = []*pb.ViewRole_ViewPolicy{{
		Name: whitelistPolicyName,
		Args: map[string]string{
			"users": "abc@example.org;dr_joe@faculty.example.edu;foo@bar.org",
		},
	}}
	err = checkAuthorization(auth.ctx, id, auth.ttl, auth.resource, auth.view, auth.role, auth.cfg, test.TestClientID, auth.dam.ValidateCfgOpts(storage.DefaultRealm, nil))
	if err != nil {
		t.Errorf("whitelist by email: checkAuthorization(ctx, id, %v, %q, %q, %q, cfg, %q) failed: %v", auth.ttl, auth.resource, auth.view, auth.role, test.TestClientID, err)
	}

	// Use group membership whitelist
	auth.cfg.Resources[auth.resource].Views[auth.view].Roles[auth.role].Policies = []*pb.ViewRole_ViewPolicy{{
		Name: whitelistPolicyName,
		Args: map[string]string{
			"groups": "whitelisted",
		},
	}}
	err = checkAuthorization(auth.ctx, id, auth.ttl, auth.resource, auth.view, auth.role, auth.cfg, test.TestClientID, auth.dam.ValidateCfgOpts(storage.DefaultRealm, nil))
	if err != nil {
		t.Errorf("whitelist by group membership: checkAuthorization(ctx, id, %v, %q, %q, %q, cfg, %q) failed: %v", auth.ttl, auth.resource, auth.view, auth.role, test.TestClientID, err)
	}
}

func Test_populateIdentityVisas_oidc_and_jku(t *testing.T) {
	store := storage.NewMemoryStorage("dam", "testdata/config")
	broker, err := persona.NewBroker(hydraPublicURL, &testkeys.PersonaBrokerKey, "dam", "testdata/config", false)
	if err != nil {
		t.Fatalf("NewBroker() failed: %v", err)
	}

	s := NewService(&Options{
		HTTPClient:     httptestclient.New(broker.Handler),
		Domain:         "https://test.org",
		ServiceName:    "dam",
		DefaultBroker:  testBroker,
		Store:          store,
		UseHydra:       useHydra,
		HydraAdminURL:  hydraAdminURL,
		HydraPublicURL: hydraPublicURL,
		HydraSyncFreq:  time.Nanosecond,
		Encryption:     fakeencryption.New(),
	})

	cfg, err := s.loadConfig(nil, storage.DefaultRealm)
	if err != nil {
		t.Fatalf("loadConfig() failed: %v", err)
	}

	ctx := oidc.ClientContext(context.Background(), httptestclient.New(broker.Handler))

	signer := localsign.New(&testkeys.PersonaBrokerKey)
	v1, err := ga4gh.NewVisaFromData(ctx, &ga4gh.VisaData{
		StdClaims: ga4gh.StdClaims{
			Issuer:    hydraPublicURL,
			Subject:   "subject1",
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
		Assertion: ga4gh.Assertion{
			Type:     "AffiliationAndRole",
			Value:    "faculty@issuer0.org",
			Source:   "http://testkeys-visa-issuer-0.org",
			By:       "so",
			Asserted: 10000,
		},
		Scope: "openid",
	}, "", signer)
	if err != nil {
		t.Fatalf("NewVisaFromData() v1 failed: %v", err)
	}

	v2, err := ga4gh.NewVisaFromData(ctx, &ga4gh.VisaData{
		StdClaims: ga4gh.StdClaims{
			Issuer:    hydraPublicURL,
			Subject:   "subject1",
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
		Assertion: ga4gh.Assertion{
			Type:     "AcceptedTermsAndPolicies",
			Value:    "https://agreements.example.org/ds123",
			Source:   "http://testkeys-visa-issuer-0.org",
			Asserted: 10100,
		},
	}, hydraPublicURL+".well-known/jwks", signer)
	if err != nil {
		t.Fatalf("NewVisaFromData() v2 failed: %v", err)
	}

	id := &ga4gh.Identity{
		VisaJWTs: []string{string(v1.JWT()), string(v2.JWT())},
	}
	id, err = s.populateIdentityVisas(ctx, id, cfg)
	if err != nil {
		t.Fatalf("populateIdentityVisas failed: %v", err)
	}

	got := id.GA4GH
	for k := range got {
		for i := range got[k] {
			got[k][i].Expires = 0
			got[k][i].VisaData.ExpiresAt = 0
		}
	}

	want := map[string][]ga4gh.OldClaim{
		"AcceptedTermsAndPolicies": {
			{
				Value:    "https://agreements.example.org/ds123",
				Source:   "http://testkeys-visa-issuer-0.org",
				Asserted: 10100,
				Issuer:   "https://hydra.example.com/",
				VisaData: &ga4gh.VisaData{
					StdClaims: ga4gh.StdClaims{Issuer: "https://hydra.example.com/", Subject: "subject1"},
					Assertion: ga4gh.Assertion{
						Type:     "AcceptedTermsAndPolicies",
						Value:    "https://agreements.example.org/ds123",
						Source:   "http://testkeys-visa-issuer-0.org",
						Asserted: 10100,
					},
				},
				TokenFormat: "document",
			},
		},
		"AffiliationAndRole": {
			{
				Value:    "faculty@issuer0.org",
				Source:   "http://testkeys-visa-issuer-0.org",
				Asserted: 10000,
				By:       "so",
				Issuer:   "https://hydra.example.com/",
				VisaData: &ga4gh.VisaData{
					StdClaims: ga4gh.StdClaims{Issuer: "https://hydra.example.com/", Subject: "subject1"},
					Scope:     "openid",
					Assertion: ga4gh.Assertion{
						Type:     "AffiliationAndRole",
						Value:    "faculty@issuer0.org",
						Source:   "http://testkeys-visa-issuer-0.org",
						By:       "so",
						Asserted: 10000,
					},
				},
				TokenFormat: "access_token",
			},
		},
	}
	if d := cmp.Diff(want, got); len(d) > 0 {
		t.Errorf("populateIdentityVisas() (-want, +got): %s", d)
	}

	if len(id.RejectedVisas) > 0 {
		t.Errorf("RejectedVisas should be empty: %+v", id.RejectedVisas)
	}
}

func setupHydraTest(readOnlyMasterRealm bool) (*Service, *pb.DamConfig, *pb.DamSecrets, *fakehydra.Server, *persona.Server, error) {
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
		ServiceName:    "dam",
		DefaultBroker:  testBroker,
		Store:          store,
		Warehouse:      wh,
		UseHydra:       useHydra,
		HydraAdminURL:  hydraAdminURL,
		HydraPublicURL: hydraPublicURL,
		HydraSyncFreq:  time.Nanosecond,
		Encryption:     fakeencryption.New(),
	})

	cfg, err := s.loadConfig(nil, storage.DefaultRealm)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	cfg.Options.ReadOnlyMasterRealm = readOnlyMasterRealm
	if err := s.store.Write(storage.ConfigDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, cfg, nil); err != nil {
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
	s, cfg, _, h, _, err := setupHydraTest(true)
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	ga4ghGCSViewer := url.QueryEscape("https://test.org/dam/master/resources/ga4gh-apis/views/gcs_read/roles/viewer/interfaces/http:gcp:gs")
	ga4ghBeaconDiscovery := url.QueryEscape("https://test.org/dam/master/resources/ga4gh-apis/views/beacon/roles/discovery/interfaces/http:beacon")
	// TODO: remove support for oldResourcePath
	oldGCSViewer := url.QueryEscape("https://test.org/dam/master/resources/ga4gh-apis/views/gcs_read/roles/viewer")

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
		{
			name:              "old resource path",
			authParams:        "max_age=10&resource=" + oldGCSViewer,
			wantTTL:           int64(10 * time.Second),
			wantResourceCount: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := sendLogin(s, cfg, h, tc.authParams, nil)
			if resp.StatusCode != http.StatusSeeOther {
				t.Errorf("resp.StatusCode wants %d, got %d", http.StatusSeeOther, resp.StatusCode)
			}

			idpc := cfg.TrustedIssuers[s.defaultBroker]

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
	s, cfg, _, h, _, err := setupHydraTest(true)
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	ga4ghGCSViewer := url.QueryEscape("https://test.org/dam/master/resources/ga4gh-apis/views/gcs_read/roles/viewer/interfaces/http:gcp:gs")

	tests := []struct {
		name       string
		authParams string
		errCode    int64
	}{
		{
			name:       "max_age wrong format",
			authParams: "max_age=1h&resource=" + ga4ghGCSViewer,
			errCode:    http.StatusBadRequest,
		},
		{
			name:       "negative max_age",
			authParams: "max_age=-1000&resource=" + ga4ghGCSViewer,
			errCode:    http.StatusBadRequest,
		},
		{
			name:       "max_age more than maxTTL",
			authParams: "max_age=9999999&resource=" + ga4ghGCSViewer,
			errCode:    http.StatusBadRequest,
		},
		{
			name:       "negative ttl",
			authParams: "ttl=-1d&resource=" + ga4ghGCSViewer,
			errCode:    http.StatusBadRequest,
		},
		{
			name:       "ttl more than maxTTL",
			authParams: "ttl=100d&resource=" + ga4ghGCSViewer,
			errCode:    http.StatusBadRequest,
		},
		{
			name:       "no resource",
			authParams: "",
			errCode:    http.StatusBadRequest,
		},
		{
			name:       "resource without domain",
			authParams: "resource=dam/master/resources/ga4gh-apis/views/gcs_read/roles/viewer",
			errCode:    http.StatusBadRequest,
		},
		{
			name:       "resource wrong format",
			authParams: "resource=" + strings.ReplaceAll(ga4ghGCSViewer, "resources", "invalid"),
			errCode:    http.StatusBadRequest,
		},
		{
			name:       "resource not exist",
			authParams: "resource=" + strings.ReplaceAll(ga4ghGCSViewer, "ga4gh-apis", "invalid"),
			errCode:    http.StatusNotFound,
		},
		{
			name:       "resource view not exist",
			authParams: "resource=" + strings.ReplaceAll(ga4ghGCSViewer, "gcs_read", "invalid"),
			errCode:    http.StatusNotFound,
		},
		{
			name:       "resource view role not exist",
			authParams: "resource=" + strings.ReplaceAll(ga4ghGCSViewer, "viewer", "invalid"),
			errCode:    http.StatusBadRequest,
		},
		{
			name:       "resource interface not exist",
			authParams: "resource=" + strings.ReplaceAll(ga4ghGCSViewer, "gcp", "invalid"),
			errCode:    http.StatusBadRequest,
		},
		{
			name:       "second resource invalid",
			authParams: "resource=" + ga4ghGCSViewer + "&resource=invalid",
			errCode:    http.StatusBadRequest,
		},
		{
			name:       "resource not at same realm",
			authParams: "resource=" + ga4ghGCSViewer + "&resource=" + strings.ReplaceAll(ga4ghGCSViewer, "master", "test"),
			errCode:    http.StatusConflict,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h.Clear()
			h.RejectLoginResp = &hydraapi.RequestHandlerResponse{RedirectTo: hydraPublicURL}

			resp := sendLogin(s, cfg, h, tc.authParams, nil)
			if resp.StatusCode != http.StatusSeeOther {
				t.Errorf("StatusCode = %d, wants %d", resp.StatusCode, http.StatusSeeOther)
			}

			if h.RejectLoginReq.Code != tc.errCode {
				t.Errorf("RejectLoginReq.Code = %d, wants %d", h.RejectLoginReq.Code, tc.errCode)
			}
		})
	}
}

func TestLogin_LoginHint_Hydra_Success(t *testing.T) {
	s, cfg, _, h, _, err := setupHydraTest(true)
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	resp := sendLogin(s, cfg, h, "login_hint=idp:foo@bar.com", []string{"openid", "identities", "offline"})
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("resp.StatusCode wants %d, got %d", http.StatusSeeOther, resp.StatusCode)
	}

	idpc := cfg.TrustedIssuers[s.defaultBroker]

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
	s, cfg, _, h, _, err := setupHydraTest(true)
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	resp := sendLogin(s, cfg, h, "", []string{"openid", "identities", "offline"})
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("resp.StatusCode wants %d, got %d", http.StatusSeeOther, resp.StatusCode)
	}

	idpc := cfg.TrustedIssuers[s.defaultBroker]

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

func sendLoggedIn(t *testing.T, s *Service, cfg *pb.DamConfig, h *fakehydra.Server, code, errStr, realm, state string, tokenType pb.ResourceTokenRequestState_TokenType) *http.Response {
	t.Helper()

	// Ensure login state exists before request.
	login := &pb.ResourceTokenRequestState{
		Challenge: loginChallenge,
		Resources: []*pb.ResourceTokenRequestState_Resource{
			{
				Realm:    realm,
				Resource: "ga4gh-apis",
				View:     "gcs_read",
				Role:     "viewer",
			},
		},
		Ttl:    int64(time.Hour),
		Broker: testBroker,
		Realm:  realm,
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
	u := damURL + loggedInPath
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, u, nil)
	v := url.Values{}
	if len(code) > 0 {
		v.Set("code", code)
	}
	if len(state) > 0 {
		v.Set("state", state)
	}
	if len(errStr) > 0 {
		v.Set("error", errStr)
	}
	r.URL.RawQuery = v.Encode()

	s.Handler.ServeHTTP(w, r)

	return w.Result()
}

func TestLoggedIn_Hydra_Success(t *testing.T) {
	s, cfg, _, h, _, err := setupHydraTest(true)
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	pname := "dr_joe_elixir"

	resp := sendLoggedIn(t, s, cfg, h, pname, "", storage.DefaultRealm, loginStateID, pb.ResourceTokenRequestState_DATASET)

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("resp.StatusCode wants %d got %d", http.StatusSeeOther, resp.StatusCode)
	}

	l := resp.Header.Get("Location")
	if l != hydraPublicURL {
		t.Errorf("Location wants %s got %s", hydraPublicURL, l)
	}

	st, ok := h.AcceptLoginReq.Context[stateIDInHydra]
	if !ok {
		t.Errorf("AcceptLoginReq.Context[%s] not exists", stateIDInHydra)
	}
	stateID, ok := st.(string)
	if !ok {
		t.Errorf("AcceptLoginReq.Context[%s] is wrong type", stateIDInHydra)
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

func TestLoggedIn_Hydra_Success_Log(t *testing.T) {
	s, cfg, _, h, _, err := setupHydraTest(true)
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}
	logs, close := fakesdl.New()
	defer close()
	s.logger = logs.Client

	serviceinfo.Project = "p1"
	serviceinfo.Type = "t1"
	serviceinfo.Name = "n1"

	pname := "dr_joe_elixir"

	sendLoggedIn(t, s, cfg, h, pname, "", storage.DefaultRealm, loginStateID, pb.ResourceTokenRequestState_DATASET)

	logs.Client.Close()
	got := logs.Server.Logs[0].Entries[0]

	want := &lepb.LogEntry{
		Payload:  &lepb.LogEntry_JsonPayload{},
		Severity: lspb.LogSeverity_DEFAULT,
		Labels: map[string]string{
			"type":            auditlog.TypePolicyLog,
			"token_id":        "token-id-dr_joe_elixir",
			"token_subject":   got.Labels["token_subject"],
			"token_issuer":    "https://hydra.example.com/",
			"pass_auth_check": "true",
			"error_type":      "",
			"resource":        "master/ga4gh-apis/gcs_read/viewer",
			"ttl":             "1h",
			"project_id":      "p1",
			"service_type":    "t1",
			"service_name":    "n1",
			"cart_id":         "ls-1234",
			"config_revision": "1",
		},
	}

	got.Timestamp = nil
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Fatalf("Logs returned diff (-want +got):\n%s", diff)
	}
}

func TestLoggedIn_Hydra_Success_CreateAccount(t *testing.T) {
	realms := []string{"master", "test"}

	for _, realm := range realms {
		t.Run(realm, func(t *testing.T) {
			s, cfg, _, h, _, err := setupHydraTest(true)
			if err != nil {
				t.Fatalf("setupHydraTest() failed: %v", err)
			}
			logs, close := fakesdl.New()
			defer close()
			s.logger = logs.Client

			serviceinfo.Project = "p1"
			serviceinfo.Type = "t1"
			serviceinfo.Name = "n1"

			pname := "dr_joe_elixir"

			sendLoggedIn(t, s, cfg, h, pname, "", realm, loginStateID, pb.ResourceTokenRequestState_DATASET)

			lookup, err := s.scim.LoadAccountLookup(realm, pname, nil)
			if err != nil {
				t.Fatalf("LoadAccountLookup() failed: %v", err)
			}

			got, _, err := s.scim.LoadAccount(lookup.Subject, realm, true, nil)
			if err != nil {
				t.Fatalf("LoadAccount() failed: %v", err)
			}

			if got == nil || len(got.ConnectedAccounts) == 0 {
				t.Fatalf("LoadAccount() = %+v", got)
			}

			want := &cpb.Account{
				ConnectedAccounts: []*cpb.ConnectedAccount{
					{
						Profile: &cpb.AccountProfile{
							Username:   pname,
							Name:       "Dr Joe (Elixir)",
							GivenName:  "Dr",
							FamilyName: "Joe",
							Picture:    "/identity/static/images/elixir_identity.png",
						},
						Properties: &cpb.AccountProperties{
							Subject:  pname,
							Email:    "dr_joe@faculty.example.edu",
							Created:  got.ConnectedAccounts[0].Properties.Created,
							Modified: got.ConnectedAccounts[0].Properties.Modified,
						},
						Provider:     testBroker,
						Refreshed:    got.ConnectedAccounts[0].Refreshed,
						Revision:     1,
						LinkRevision: 1,
						Passport:     &cpb.Passport{InternalEncryptedVisas: got.ConnectedAccounts[0].Passport.InternalEncryptedVisas},
					},
				},
				Profile: &cpb.AccountProfile{
					Username:   pname,
					Name:       "Dr Joe (Elixir)",
					GivenName:  "Dr",
					FamilyName: "Joe",
					Picture:    "/identity/static/images/elixir_identity.png",
				},
				Properties: &cpb.AccountProperties{
					Subject:  lookup.Subject,
					Email:    "dr_joe@faculty.example.edu",
					Created:  got.Properties.Created,
					Modified: got.Properties.Modified,
				},
				Revision: 1,
				State:    "ACTIVE",
			}

			if d := cmp.Diff(want, got, protocmp.Transform()); len(d) > 0 {
				t.Errorf("LoadAccount() = (-want, +got): %s", d)
			}
		})
	}
}

func TestLoggedIn_Hydra_Success_UpdateAccount(t *testing.T) {
	realms := []string{"master", "test"}

	for _, realm := range realms {
		t.Run(realm, func(t *testing.T) {
			s, cfg, _, h, _, err := setupHydraTest(true)
			if err != nil {
				t.Fatalf("setupHydraTest() failed: %v", err)
			}
			logs, close := fakesdl.New()
			defer close()
			s.logger = logs.Client

			serviceinfo.Project = "p1"
			serviceinfo.Type = "t1"
			serviceinfo.Name = "n1"

			pname := "dr_joe_elixir"
			accountID := "dam_111"

			acct := &cpb.Account{
				ConnectedAccounts: []*cpb.ConnectedAccount{
					{
						Profile: &cpb.AccountProfile{
							Username: pname,
						},
						Properties: &cpb.AccountProperties{
							Subject: pname,
						},
						Provider:     testBroker,
						Revision:     4,
						LinkRevision: 1,
					},
				},
				Profile: &cpb.AccountProfile{
					Username: pname,
				},
				Properties: &cpb.AccountProperties{
					Subject: accountID,
				},
				Revision: 2,
				State:    "ACTIVE",
			}

			lookup := &cpb.AccountLookup{
				State:    "ACTIVE",
				Revision: 3,
				Subject:  accountID,
			}

			if err := s.scim.SaveAccount(nil, acct, "", accountID, realm, nil, nil); err != nil {
				t.Fatalf("SaveAccount() failed: %v", err)
			}

			if err := s.scim.SaveAccountLookup(lookup, realm, pname, nil, &ga4gh.Identity{Subject: pname}, nil); err != nil {
				t.Fatalf("SaveAccountLookup() failed: %v", err)
			}

			sendLoggedIn(t, s, cfg, h, pname, "", realm, loginStateID, pb.ResourceTokenRequestState_DATASET)

			lookup, err = s.scim.LoadAccountLookup(realm, pname, nil)
			if err != nil {
				t.Fatalf("LoadAccountLookup() failed: %v", err)
			}

			got, _, err := s.scim.LoadAccount(lookup.Subject, realm, true, nil)
			if err != nil {
				t.Fatalf("LoadAccount() failed: %v", err)
			}

			if got == nil || len(got.ConnectedAccounts) == 0 {
				t.Fatalf("LoadAccount() = %+v", got)
			}

			want := &cpb.Account{
				ConnectedAccounts: []*cpb.ConnectedAccount{
					{
						Profile: &cpb.AccountProfile{
							Username:   pname,
							Name:       "Dr Joe (Elixir)",
							GivenName:  "Dr",
							FamilyName: "Joe",
							Picture:    "/identity/static/images/elixir_identity.png",
						},
						Properties: &cpb.AccountProperties{
							Subject:  pname,
							Email:    "dr_joe@faculty.example.edu",
							Created:  got.ConnectedAccounts[0].Properties.Created,
							Modified: got.ConnectedAccounts[0].Properties.Modified,
						},
						Provider:     testBroker,
						Refreshed:    got.ConnectedAccounts[0].Refreshed,
						Revision:     5,
						LinkRevision: 1,
						Passport:     &cpb.Passport{InternalEncryptedVisas: got.ConnectedAccounts[0].Passport.InternalEncryptedVisas},
					},
				},
				Profile: &cpb.AccountProfile{
					Username: pname,
				},
				Properties: &cpb.AccountProperties{
					Subject:  accountID,
					Created:  got.Properties.Created,
					Modified: got.Properties.Modified,
				},
				Revision: 4,
				State:    "ACTIVE",
			}

			if d := cmp.Diff(want, got, protocmp.Transform()); len(d) > 0 {
				t.Errorf("LoadAccount() = (-want, +got): %s", d)
			}
		})
	}
}

func TestLoggedIn_Hydra_Errors_DisableAccount(t *testing.T) {
	s, cfg, _, h, _, err := setupHydraTest(true)
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}
	logs, close := fakesdl.New()
	defer close()
	s.logger = logs.Client

	serviceinfo.Project = "p1"
	serviceinfo.Type = "t1"
	serviceinfo.Name = "n1"

	pname := "dr_joe_elixir"
	accountID := "dam_111"

	acct := &cpb.Account{
		ConnectedAccounts: []*cpb.ConnectedAccount{
			{
				Profile: &cpb.AccountProfile{
					Username: pname,
				},
				Properties: &cpb.AccountProperties{
					Subject: pname,
				},
				Provider:     testBroker,
				Revision:     4,
				LinkRevision: 1,
			},
		},
		Profile: &cpb.AccountProfile{
			Username: pname,
		},
		Properties: &cpb.AccountProperties{
			Subject: accountID,
		},
		Revision: 2,
		State:    storage.StateDisabled,
	}

	lookup := &cpb.AccountLookup{
		State:    "ACTIVE",
		Revision: 3,
		Subject:  accountID,
	}

	if err := s.scim.SaveAccount(nil, acct, "", accountID, storage.DefaultRealm, nil, nil); err != nil {
		t.Fatalf("SaveAccount() failed: %v", err)
	}

	if err := s.scim.SaveAccountLookup(lookup, storage.DefaultRealm, pname, nil, &ga4gh.Identity{Subject: pname}, nil); err != nil {
		t.Fatalf("SaveAccountLookup() failed: %v", err)
	}

	h.RejectLoginResp = &hydraapi.RequestHandlerResponse{RedirectTo: hydraPublicURL}
	sendLoggedIn(t, s, cfg, h, pname, "", storage.DefaultRealm, loginStateID, pb.ResourceTokenRequestState_DATASET)

	if h.RejectLoginReq.Code != http.StatusForbidden {
		t.Errorf("Code = %d, wants %d", h.RejectLoginReq.Code, http.StatusForbidden)
	}
}

func TestLoggedIn_Hydra_Errors_MissingAccount(t *testing.T) {
	s, cfg, _, h, _, err := setupHydraTest(true)
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}
	logs, close := fakesdl.New()
	defer close()
	s.logger = logs.Client

	serviceinfo.Project = "p1"
	serviceinfo.Type = "t1"
	serviceinfo.Name = "n1"

	pname := "dr_joe_elixir"
	accountID := "dam_111"


	lookup := &cpb.AccountLookup{
		State:    "ACTIVE",
		Revision: 3,
		Subject:  accountID,
	}

	if err := s.scim.SaveAccountLookup(lookup, storage.DefaultRealm, pname, nil, &ga4gh.Identity{Subject: pname}, nil); err != nil {
		t.Fatalf("SaveAccountLookup() failed: %v", err)
	}

	h.RejectLoginResp = &hydraapi.RequestHandlerResponse{RedirectTo: hydraPublicURL}
	sendLoggedIn(t, s, cfg, h, pname, "", storage.DefaultRealm, loginStateID, pb.ResourceTokenRequestState_DATASET)

	if h.RejectLoginReq.Code != http.StatusServiceUnavailable {
		t.Errorf("Code = %d, wants %d", h.RejectLoginReq.Code, http.StatusServiceUnavailable)
	}
}

func TestLoggedIn_Hydra_Errors_invalid_state(t *testing.T) {
	s, cfg, _, h, _, err := setupHydraTest(true)
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
			name:       "no state",
			code:       pname,
			stateID:    "",
			respStatus: http.StatusBadRequest,
		},
		{
			name:       "stateID invalid",
			code:       pname,
			stateID:    "invalid",
			respStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := sendLoggedIn(t, s, cfg, h, tc.code, "", storage.DefaultRealm, tc.stateID, pb.ResourceTokenRequestState_DATASET)

			if resp.StatusCode != tc.respStatus {
				t.Errorf("resp.StatusCode wants %d got %d", tc.respStatus, resp.StatusCode)
			}
		})
	}
}

func TestLoggedIn_Hydra_Errors_with_challenge(t *testing.T) {
	s, cfg, _, h, _, err := setupHydraTest(true)
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	tests := []struct {
		name    string
		code    string
		stateID string
		errStr  string
		errCode int64
	}{
		{
			name:    "code invalid",
			code:    "invalid",
			stateID: loginStateID,
			errCode: http.StatusUnauthorized,
		},
		{
			name:    "user does not have enough permission",
			code:    "dr_joe_era_commons",
			stateID: loginStateID,
			errCode: http.StatusForbidden,
		},
		{
			name:    "no auth code",
			code:    "",
			stateID: loginStateID,
			errCode: http.StatusBadRequest,
		},
		{
			name:    "err upstream",
			errStr:  "err",
			stateID: loginStateID,
			errCode: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h.Clear()
			h.RejectLoginResp = &hydraapi.RequestHandlerResponse{RedirectTo: hydraPublicURL}

			resp := sendLoggedIn(t, s, cfg, h, tc.code, tc.errStr, storage.DefaultRealm, tc.stateID, pb.ResourceTokenRequestState_DATASET)

			if resp.StatusCode != http.StatusSeeOther {
				t.Errorf("StatusCode = %d, wants %d", resp.StatusCode, http.StatusSeeOther)
			}

			if h.RejectLoginReq.Code != tc.errCode {
				t.Errorf("RejectLoginReq.Code = %d, wants %d", h.RejectLoginReq.Code, tc.errCode)
			}
		})
	}
}

func TestLoggedIn_Hydra_Error_Log(t *testing.T) {
	s, cfg, _, h, _, err := setupHydraTest(true)
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}
	logs, close := fakesdl.New()
	defer close()
	s.logger = logs.Client

	h.RejectLoginResp = &hydraapi.RequestHandlerResponse{RedirectTo: hydraPublicURL}

	pname := "dr_joe_era_commons"

	sendLoggedIn(t, s, cfg, h, pname, "", storage.DefaultRealm, loginStateID, pb.ResourceTokenRequestState_DATASET)

	logs.Client.Close()

	got := logs.Server.Logs[0].Entries[0]
	if got.Labels["pass_auth_check"] == "true" {
		t.Errorf("Labels[pass_auth_check] want false")
	}
	if got.Labels["error_type"] != errRejectedPolicy {
		t.Errorf("Labels[pass_auth_check] = %s want %s", got.Labels["error_type"], errRejectedPolicy)
	}
	if got.Labels["error_type"] != errRejectedPolicy {
		t.Errorf("Labels[pass_auth_check] = %s want %s", got.Labels["error_type"], errRejectedPolicy)
	}
	if got.GetJsonPayload() == nil {
		t.Errorf("got.GetJsonPayload() want not nil")
	}
}

func TestLoggedIn_Endpoint_Hydra_Success(t *testing.T) {
	s, cfg, _, h, _, err := setupHydraTest(true)
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	pname := "dr_joe_elixir"

	resp := sendLoggedIn(t, s, cfg, h, pname, "", storage.DefaultRealm, loginStateID, pb.ResourceTokenRequestState_ENDPOINT)

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("resp.StatusCode wants %d got %d", http.StatusSeeOther, resp.StatusCode)
	}

	l := resp.Header.Get("Location")
	if l != hydraPublicURL {
		t.Errorf("Location wants %s got %s", hydraPublicURL, l)
	}

	list := h.AcceptLoginReq.Context["identities"].([]interface{})
	first := list[0].(string)
	if !strings.HasPrefix(first, "dam_") {
		t.Errorf("list[0] = %s wants 'dam_' prefix", first)
	}

	got := stringset.New()
	for _, s := range list[1:] {
		got.Add(s.(string))
	}
	want := stringset.New("dr_joe@faculty.example.edu", "dr_joe_elixir")

	if diff := cmp.Diff(want, got); len(diff) > 0 {
		t.Errorf("h.AcceptLoginReq.Context[identities] (-want, +got): %s", diff)
	}
}

func TestHydraConsent(t *testing.T) {
	s, _, _, h, _, err := setupHydraTest(true)
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

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("resp.StatusCode wants %d got %d", http.StatusSeeOther, resp.StatusCode)
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

	atid, ok := h.AcceptConsentReq.Session.AccessToken["tid"].(string)
	if !ok {
		t.Fatalf("tid in access token in wrong type")
	}

	itid, ok := h.AcceptConsentReq.Session.IDToken["tid"].(string)
	if !ok {
		t.Fatalf("tid in id token in wrong type")
	}

	if itid != atid {
		t.Errorf("tid in id token and access token should be the same, %s, %s", itid, atid)
	}
}

func TestHydraConsent_Endpoint(t *testing.T) {
	s, _, _, h, _, err := setupHydraTest(true)
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

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("resp.StatusCode wants %d got %d", http.StatusSeeOther, resp.StatusCode)
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

	atid, ok := h.AcceptConsentReq.Session.AccessToken["tid"].(string)
	if !ok {
		t.Fatalf("tid in access token in wrong type")
	}

	itid, ok := h.AcceptConsentReq.Session.IDToken["tid"].(string)
	if !ok {
		t.Fatalf("tid in id token in wrong type")
	}

	if itid != atid {
		t.Errorf("tid in id token and access token should be the same, %s, %s", itid, atid)
	}
}

func TestHydraConsent_Error(t *testing.T) {
	s, _, _, h, _, err := setupHydraTest(true)
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	h.GetConsentRequestResp = &hydraapi.ConsentRequest{}
	h.RejectConsentResp = &hydraapi.RequestHandlerResponse{RedirectTo: hydraPublicURL}

	// Send Request.
	query := fmt.Sprintf("?consent_challenge=%s", consentChallenge)
	u := damURL + hydraConsentPath + query
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, u, nil)
	s.Handler.ServeHTTP(w, r)

	resp := w.Result()

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("resp.StatusCode = %d, wants %d", resp.StatusCode, http.StatusSeeOther)
	}

	if h.RejectConsentReq.Code != http.StatusBadRequest {
		t.Errorf("RejectConsentReq.Code = %d, wants %d", h.RejectConsentReq.Code, http.StatusBadRequest)
	}
}

func sendResourceTokens(t *testing.T, s *Service, broker *persona.Server, cartID string, expired bool) *http.Response {
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

	now := time.Now().Unix()

	id := &ga4gh.Identity{
		Issuer:    hydraPublicURL,
		Subject:   "subject",
		IssuedAt:  now,
		Expiry:    now + 10000,
		Audiences: ga4gh.NewAudience(test.TestClientID),
		Extra:     map[string]interface{}{},
	}

	if expired {
		id.Expiry = 0
	}

	if len(cartID) > 0 {
		id.Extra["cart"] = cartID
	}

	tok, err := broker.Sign(nil, id)
	if err != nil {
		t.Fatalf("broker.Sign() failed: %v", err)
	}

	header := http.Header{"Authorization": []string{"Bearer " + tok}}
	return testhttp.SendTestRequest(t, s.Handler, http.MethodPost, resourceTokensPath, q, nil, header)
}

func TestResourceTokens(t *testing.T) {
	s, _, _, _, broker, err := setupHydraTest(true)
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	resp := sendResourceTokens(t, s, broker, consentStateID, false)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, wants %d", resp.StatusCode, http.StatusOK)
	}
}

func TestResourceTokens_CartNotExistsInToken(t *testing.T) {
	s, _, _, _, broker, err := setupHydraTest(true)
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	resp := sendResourceTokens(t, s, broker, "", false)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, wants %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func TestResourceTokens_CartNotExistsInStorage(t *testing.T) {
	s, _, _, _, broker, err := setupHydraTest(true)
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	resp := sendResourceTokens(t, s, broker, "invalid", false)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, wants %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestResourceTokens_TokenExpiry(t *testing.T) {
	s, _, _, _, broker, err := setupHydraTest(true)
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	resp := sendResourceTokens(t, s, broker, "invalid", true)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, wants %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func damSendTestRequest(t *testing.T, method, path, pathname, realm, personaName, clientID, clientSecret string, data proto.Message, s *Service, iss *persona.Server) *http.Response {
	t.Helper()

	var p *cpb.TestPersona
	if iss.Config() != nil {
		p = iss.Config().TestPersonas[personaName]
	}

	tok, _, err := persona.NewAccessToken(personaName, hydraPublicURL, clientID, noScope, p)
	if err != nil {
		t.Fatalf("persona.NewAccessToken(%q, %q, _, _) failed: %v", personaName, hydraPublicURL, err)
	}

	var buf bytes.Buffer
	if data != nil {
		if err := (&jsonpb.Marshaler{}).Marshal(&buf, data); err != nil {
			t.Fatal(fmt.Errorf("marshaling message %+v failed: %v", data, err))
		}
	}

	path = strings.ReplaceAll(path, "{realm}", realm)
	path = strings.ReplaceAll(path, "{name}", pathname)
	q := url.Values{
		"client_id":     []string{clientID},
		"client_secret": []string{clientSecret},
	}
	h := http.Header{"Authorization": []string{"Bearer " + string(tok)}}
	return testhttp.SendTestRequest(t, s.Handler, method, path, q, &buf, h)
}

func TestClients_Get(t *testing.T) {
	s, cfg, sec, _, iss, err := setupHydraTest(false)
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientName := "test_client"
	pname := "non-admin"
	cli := cfg.Clients[clientName]

	resp := damSendTestRequest(t, http.MethodGet, clientPath, clientName, "master", pname, cli.ClientId, sec.ClientSecrets[cli.ClientId], nil, s, iss)

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
	s, _, _, _, iss, err := setupHydraTest(false)
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	tests := []struct {
		name       string
		clientName string
		realm      string
		status     int
	}{
		{
			name:       "client not exists",
			clientName: "invalid",
			realm:      "master",
			status:     http.StatusNotFound,
		},
		{
			name:       "client id and client name not match",
			clientName: "test_client2",
			realm:      "master",
			status:     http.StatusNotFound,
		},
		{
			name:       "not master realm",
			clientName: "test_client",
			realm:      "test",
			status:     http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pname := "non-admin"

			resp := damSendTestRequest(t, http.MethodGet, clientPath, tc.clientName, tc.realm, pname, test.TestClientID, test.TestClientSecret, nil, s, iss)

			if resp.StatusCode != tc.status {
				t.Errorf("resp.StatusCode = %d, wants %d", resp.StatusCode, tc.status)
			}
		})
	}
}

func TestSyncClients_Get(t *testing.T) {
	s, cfg, sec, _, iss, err := setupHydraTest(true)
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientName := "test_client"
	cli := cfg.Clients[clientName]

	resp := damSendTestRequest(t, http.MethodGet, syncClientsPath, clientName, "master", "", cli.ClientId, sec.ClientSecrets[cli.ClientId], nil, s, iss)

	wantStatus := http.StatusOK
	if resp.StatusCode != wantStatus {
		t.Errorf("syncClients resp.StatusCode = %d, want %d", resp.StatusCode, wantStatus)
	}
	got := &cpb.ClientState{}
	if err := jsonpb.Unmarshal(resp.Body, got); err != nil && err != io.EOF {
		t.Fatalf("jsonpb.Unmarshal() failed: %v", err)
	}
	if codes.Code(got.Status.Code) != codes.OK {
		t.Errorf("syncClients status code mismatch: got code %d, want code %d, got body: %+v", got.Status.Code, codes.OK, got)
	}
}

func TestSyncClients_Post(t *testing.T) {
	s, cfg, sec, _, iss, err := setupHydraTest(true)
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientName := "test_client"
	cli := cfg.Clients[clientName]

	resp := damSendTestRequest(t, http.MethodPost, syncClientsPath, clientName, "master", "", cli.ClientId, sec.ClientSecrets[cli.ClientId], nil, s, iss)

	wantStatus := http.StatusOK
	if resp.StatusCode != wantStatus {
		t.Errorf("syncClients resp.StatusCode = %d, want %d", resp.StatusCode, wantStatus)
	}
	got := &cpb.ClientState{}
	if err := jsonpb.Unmarshal(resp.Body, got); err != nil && err != io.EOF {
		t.Fatalf("jsonpb.Unmarshal() failed: %v", err)
	}
	if codes.Code(got.Status.Code) != codes.OK {
		t.Errorf("syncClients status code mismatch: got code %d, want code %d, got body: %+v", got.Status.Code, codes.OK, got)
	}
}

func TestSyncClients_ScopeError(t *testing.T) {
	s, cfg, sec, _, iss, err := setupHydraTest(true)
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientName := "test_client2"
	cli := cfg.Clients[clientName]

	resp := damSendTestRequest(t, http.MethodGet, syncClientsPath, clientName, "master", "", cli.ClientId, sec.ClientSecrets[cli.ClientId], nil, s, iss)

	wantStatus := http.StatusForbidden
	if resp.StatusCode != wantStatus {
		t.Fatalf("clientsSync resp.StatusCode mismatch: got %d, want %d", resp.StatusCode, wantStatus)
	}
}

func sendConfigClientsGet(t *testing.T, pname, clientName, realm, clientID, clientSecret string, s *Service, iss *persona.Server) *http.Response {
	t.Helper()

	var p *cpb.TestPersona
	if iss.Config() != nil {
		p = iss.Config().TestPersonas[pname]
	}

	tok, _, err := persona.NewAccessToken(pname, hydraPublicURL, clientID, noScope, p)
	if err != nil {
		t.Fatalf("persona.NewAccessToken(%q, %q, _, _) failed: %v", pname, hydraPublicURL, err)
	}

	path := strings.ReplaceAll(configClientPath, "{realm}", realm)
	path = strings.ReplaceAll(path, "{name}", clientName)
	q := url.Values{
		"client_id":     []string{clientID},
		"client_secret": []string{clientSecret},
	}
	h := http.Header{"Authorization": []string{"Bearer " + string(tok)}}
	return testhttp.SendTestRequest(t, s.Handler, http.MethodGet, path, q, nil, h)
}

func TestConfigClients_Get(t *testing.T) {
	s, cfg, sec, _, iss, err := setupHydraTest(false)
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientName := "test_client"
	pname := "admin"
	cli := cfg.Clients[clientName]

	resp := sendConfigClientsGet(t, pname, clientName, "master", cli.ClientId, sec.ClientSecrets[cli.ClientId], s, iss)

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
	s, _, _, _, iss, err := setupHydraTest(false)
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	tests := []struct {
		name       string
		persona    string
		clientName string
		realm      string
		status     int
	}{
		{
			name:       "client not exists",
			persona:    "admin",
			clientName: "invalid",
			realm:      "master",
			status:     http.StatusNotFound,
		},
		{
			name:       "not admin",
			persona:    "non-admin",
			clientName: "test_client",
			realm:      "master",
			status:     http.StatusUnauthorized,
		},
		{
			name:       "not master realm",
			persona:    "admin",
			clientName: "test_client",
			realm:      "test",
			status:     http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := sendConfigClientsGet(t, tc.persona, tc.clientName, tc.realm, test.TestClientID, test.TestClientSecret, s, iss)

			if resp.StatusCode != tc.status {
				t.Errorf("resp.StatusCode = %d, wants %d", resp.StatusCode, tc.status)
			}
		})
	}
}

func diffOfHydraClientIgnoreClientIDAndSecret(c1 *hydraapi.Client, c2 *hydraapi.Client) string {
	return cmp.Diff(c1, c2, cmpopts.IgnoreFields(hydraapi.Client{}, "ClientID", "Secret"), cmpopts.IgnoreUnexported(strfmt.DateTime{}))
}

func sendConfigClientsCreate(t *testing.T, pname, clientName, realm, clientID, clientSecret string, cli *cpb.Client, s *Service, iss *persona.Server) *http.Response {
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

	path := strings.ReplaceAll(configClientPath, "{realm}", realm)
	path = strings.ReplaceAll(path, "{name}", clientName)
	q := url.Values{
		"client_id":     []string{clientID},
		"client_secret": []string{clientSecret},
	}
	h := http.Header{"Authorization": []string{"Bearer " + string(tok)}}
	return testhttp.SendTestRequest(t, s.Handler, http.MethodPost, path, q, &buf, h)
}

func TestConfigClients_Create_Success(t *testing.T) {
	s, _, _, h, iss, err := setupHydraTest(false)
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

	resp := sendConfigClientsCreate(t, pname, clientName, "master", test.TestClientID, test.TestClientSecret, cli, s, iss)
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
		Audience:      []string{h.CreateClientReq.ClientID},
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
	s, _, _, h, iss, err := setupHydraTest(false)
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

	resp := sendConfigClientsCreate(t, pname, clientName, "master", test.TestClientID, test.TestClientSecret, cli, s, iss)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status=%d, wants %d", resp.StatusCode, http.StatusOK)
	}

	conf, err := s.loadConfig(nil, "master")
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
	s, _, _, h, iss, err := setupHydraTest(false)
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
		realm      string
		client     *cpb.Client
		status     int
	}{
		{
			name:       "client exists",
			persona:    "admin",
			clientName: "test_client",
			realm:      "master",
			client:     cli,
			status:     http.StatusConflict,
		},
		{
			name:       "not admin",
			persona:    "non-admin",
			clientName: clientName,
			realm:      "master",
			client:     cli,
			status:     http.StatusUnauthorized,
		},
		{
			name:       "no redirect",
			persona:    "admin",
			clientName: clientName,
			realm:      "master",
			client:     &cpb.Client{Ui: cli.Ui},
			status:     http.StatusBadRequest,
		},
		{
			name:       "no ui",
			persona:    "admin",
			clientName: clientName,
			realm:      "master",
			client:     &cpb.Client{RedirectUris: cli.RedirectUris},
			status:     http.StatusBadRequest,
		},
		{
			name:       "not master realm",
			persona:    "admin",
			clientName: clientName,
			realm:      "test",
			client:     cli,
			status:     http.StatusForbidden,
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

			resp := sendConfigClientsCreate(t, tc.persona, tc.clientName, tc.realm, test.TestClientID, test.TestClientSecret, tc.client, s, iss)

			if resp.StatusCode != tc.status {
				t.Errorf("resp.StatusCode = %d, wants %d", resp.StatusCode, tc.status)
			}

			if h.CreateClientReq != nil {
				t.Errorf("should not call create client to hydra")
			}

			conf, err := s.loadConfig(nil, tc.realm)
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
	s, _, _, h, iss, err := setupHydraTest(false)
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

	resp := sendConfigClientsCreate(t, "admin", clientName, "master", test.TestClientID, test.TestClientSecret, cli, s, iss)

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("resp.StatusCode = %d, wants %d", resp.StatusCode, http.StatusServiceUnavailable)
	}

	conf, err := s.loadConfig(nil, "master")
	if err != nil {
		t.Fatalf("s.loadConfig() failed %v", err)
	}
	if _, ok := conf.Clients[clientName]; ok {
		t.Errorf("conf.Clients[%s] should not exists in storage", clientName)
	}
}

func sendConfigClientsUpdate(t *testing.T, pname, clientName, realm, clientID, clientSecret string, cli *cpb.Client, s *Service, iss *persona.Server) *http.Response {
	t.Helper()

	return damSendTestRequest(t, http.MethodPatch, configClientPath, clientName, realm, pname, clientID, clientSecret, &cpb.ConfigClientRequest{Item: cli}, s, iss)
}

func TestConfigClients_Update_Success(t *testing.T) {
	s, cfg, sec, h, iss, err := setupHydraTest(false)
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

	resp := sendConfigClientsUpdate(t, pname, clientName, "master", test.TestClientID, test.TestClientSecret, cli, s, iss)
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
	s, _, _, h, iss, err := setupHydraTest(false)
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

	resp := sendConfigClientsUpdate(t, pname, clientName, "master", test.TestClientID, test.TestClientSecret, cli, s, iss)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status=%d, wants %d", resp.StatusCode, http.StatusOK)
	}

	conf, err := s.loadConfig(nil, "master")
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
	s, cfg, _, h, iss, err := setupHydraTest(false)
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
		realm      string
		status     int
	}{
		{
			name:       "client not exists",
			persona:    "admin",
			clientName: "invalid",
			realm:      "master",
			status:     http.StatusNotFound,
		},
		{
			name:       "not admin",
			persona:    "non-admin",
			clientName: clientName,
			realm:      "master",
			status:     http.StatusUnauthorized,
		},
		{
			name:       "not master realm",
			persona:    "admin",
			clientName: clientName,
			realm:      "test",
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

			resp := sendConfigClientsUpdate(t, tc.persona, tc.clientName, tc.realm, test.TestClientID, test.TestClientSecret, cli, s, iss)

			if resp.StatusCode != tc.status {
				t.Errorf("resp.StatusCode = %d, wants %d", resp.StatusCode, tc.status)
			}

			if h.UpdateClientReq != nil {
				t.Errorf("should not call Update client to hydra")
			}

			conf, err := s.loadConfig(nil, "master")
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
	s, cfg, _, h, iss, err := setupHydraTest(false)
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

	resp := sendConfigClientsUpdate(t, "admin", clientName, "master", test.TestClientID, test.TestClientSecret, cli, s, iss)

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("resp.StatusCode = %d, wants %d", resp.StatusCode, http.StatusServiceUnavailable)
	}

	conf, err := s.loadConfig(nil, "master")
	if err != nil {
		t.Fatalf("s.loadConfig() failed %v", err)
	}
	if diff := cmp.Diff(cfg, conf, protocmp.Transform()); len(diff) != 0 {
		t.Errorf("config should not update, (-want, +got): %s", diff)
	}
}

func sendConfigClientsDelete(t *testing.T, pname, clientName, realm, clientID, clientSecret string, s *Service, iss *persona.Server) *http.Response {
	t.Helper()

	var p *cpb.TestPersona
	if iss.Config() != nil {
		p = iss.Config().TestPersonas[pname]
	}

	tok, _, err := persona.NewAccessToken(pname, hydraPublicURL, clientID, noScope, p)
	if err != nil {
		t.Fatalf("persona.NewAccessToken(%q, %q, _, _) failed: %v", pname, hydraPublicURL, err)
	}

	path := strings.ReplaceAll(configClientPath, "{realm}", realm)
	path = strings.ReplaceAll(path, "{name}", clientName)
	q := url.Values{
		"client_id":     []string{clientID},
		"client_secret": []string{clientSecret},
	}
	h := http.Header{"Authorization": []string{"Bearer " + string(tok)}}
	return testhttp.SendTestRequest(t, s.Handler, http.MethodDelete, path, q, nil, h)
}

func TestConfigClients_Delete_Success(t *testing.T) {
	s, _, _, _, iss, err := setupHydraTest(false)
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientName := "test_client"

	pname := "admin"

	resp := sendConfigClientsDelete(t, pname, clientName, "master", test.TestClientID, test.TestClientSecret, s, iss)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("resp.StatusCode = %d, wants %d", resp.StatusCode, http.StatusOK)
	}

	conf, err := s.loadConfig(nil, "master")
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
	s, cfg, _, h, iss, err := setupHydraTest(false)
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientName := "test_client"

	tests := []struct {
		name       string
		persona    string
		clientName string
		realm      string
		status     int
	}{
		{
			name:       "client not exists",
			persona:    "admin",
			clientName: "invalid",
			realm:      "master",
			status:     http.StatusNotFound,
		},
		{
			name:       "not admin",
			persona:    "non-admin",
			clientName: clientName,
			realm:      "master",
			status:     http.StatusUnauthorized,
		},
		{
			name:       "not master realm",
			persona:    "admin",
			clientName: clientName,
			realm:      "test",
			status:     http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h.Clear()

			resp := sendConfigClientsDelete(t, tc.persona, tc.clientName, tc.realm, test.TestClientID, test.TestClientSecret, s, iss)

			if resp.StatusCode != tc.status {
				t.Errorf("resp.StatusCode = %d, wants %d", resp.StatusCode, tc.status)
			}

			conf, err := s.loadConfig(nil, tc.realm)
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
	s, cfg, _, h, iss, err := setupHydraTest(false)
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientName := "test_client"

	h.DeleteClientErr = &hydraapi.GenericError{Code: http.StatusServiceUnavailable}

	resp := sendConfigClientsDelete(t, "admin", clientName, "master", test.TestClientID, test.TestClientSecret, s, iss)

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("resp.StatusCode = %d, wants %d", resp.StatusCode, http.StatusServiceUnavailable)
	}

	conf, err := s.loadConfig(nil, "master")
	if err != nil {
		t.Fatalf("s.loadConfig() failed %v", err)
	}
	if diff := cmp.Diff(cfg, conf, protocmp.Transform()); len(diff) != 0 {
		t.Errorf("config should not update, (-want, +got): %s", diff)
	}
}

func TestConfig_Hydra_Put(t *testing.T) {
	s, _, _, h, iss, err := setupHydraTest(false)
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	cfg, err := s.loadConfig(nil, "master")
	if err != nil {
		t.Fatalf(`s.loadConfig(_, "master") failed %v`, err)
	}
	sec, err := s.loadSecrets(nil)
	if err != nil {
		t.Fatalf("s.loadSecrets(_) failed %v", err)
	}

	clientName := "test_client"
	cli, ok := cfg.Clients[clientName]
	if !ok {
		t.Fatalf("client %q not defined in config", clientName)
	}

	existing := []*hydraapi.Client{}
	for name, c := range cfg.Clients {
		existing = append(existing, &hydraapi.Client{
			Name:          name,
			ClientID:      c.ClientId,
			Secret:        sec.ClientSecrets[c.ClientId],
			RedirectURIs:  c.RedirectUris,
			Scope:         defaultScope,
			GrantTypes:    defaultGrantTypes,
			ResponseTypes: defaultResponseTypes,
		})
	}
	h.ListClientsResp = existing
	h.UpdateClientResp = &hydraapi.Client{
		ClientID:      cli.ClientId,
		Name:          clientName,
		Secret:        "secret",
		RedirectURIs:  cli.RedirectUris,
		Scope:         defaultScope,
		GrantTypes:    defaultGrantTypes,
		ResponseTypes: defaultResponseTypes,
	}

	pname := "admin"
	updatedScope := cli.Scope + " new-scope"
	cli.Scope = updatedScope

	// Call update config.
	resp := damSendTestRequest(t, http.MethodPut, configPath, "", "master", pname, test.TestClientID, test.TestClientSecret, &pb.ConfigRequest{Item: cfg}, s, iss)
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		t.Fatalf("damSendTestRequest().StatusCode = %d, want %d\n body: %v", resp.StatusCode, http.StatusOK, string(body))
	}

	got := &pb.ConfigResponse{}
	if err := jsonpb.Unmarshal(resp.Body, got); err != nil && err != io.EOF {
		t.Fatalf("jsonpb.Unmarshal() failed: %v", err)
	}

	wantReq := &hydraapi.Client{
		Name:          clientName,
		GrantTypes:    cli.GrantTypes,
		ResponseTypes: cli.ResponseTypes,
		Scope:         updatedScope,
		RedirectURIs:  cli.RedirectUris,
		Audience:      []string{cli.ClientId},
	}
	if diff := diffOfHydraClientIgnoreClientIDAndSecret(wantReq, h.UpdateClientReq); len(diff) > 0 {
		t.Errorf("client (-want, +got): %s", diff)
	}

	wantResp := &pb.ConfigResponse{}
	if diff := cmp.Diff(wantResp, got, protocmp.Transform()); len(diff) > 0 {
		t.Errorf("response (-want, +got): %s", diff)
	}
}

func TestConfig_Hydra_Put_NotMasterRealmError(t *testing.T) {
	s, _, _, h, iss, err := setupHydraTest(true)
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	cfg, err := s.loadConfig(nil, "test")
	if err != nil {
		t.Fatalf(`s.loadConfig(_, "test") failed %v`, err)
	}
	sec, err := s.loadSecrets(nil)
	if err != nil {
		t.Fatalf("s.loadSecrets(_) failed %v", err)
	}

	clientName := "test_client"
	cli, ok := cfg.Clients[clientName]
	if !ok {
		t.Fatalf("client %q not defined in config", clientName)
	}

	var existing []*hydraapi.Client
	for name, c := range cfg.Clients {
		existing = append(existing, &hydraapi.Client{
			Name:          name,
			ClientID:      c.ClientId,
			Secret:        sec.ClientSecrets[c.ClientId],
			RedirectURIs:  c.RedirectUris,
			Scope:         defaultScope,
			GrantTypes:    defaultGrantTypes,
			ResponseTypes: defaultResponseTypes,
		})
	}
	h.ListClientsResp = existing
	h.UpdateClientResp = &hydraapi.Client{
		ClientID:      cli.ClientId,
		Name:          clientName,
		Secret:        "secret",
		RedirectURIs:  cli.RedirectUris,
		Scope:         defaultScope,
		GrantTypes:    defaultGrantTypes,
		ResponseTypes: defaultResponseTypes,
	}

	pname := "admin"
	updatedScope := cli.Scope + " new-scope"
	cli.Scope = updatedScope

	// Call update config.
	resp := damSendTestRequest(t, http.MethodPut, configPath, "", "test", pname, test.TestClientID, test.TestClientSecret, &pb.ConfigRequest{Item: cfg}, s, iss)
	if resp.StatusCode != http.StatusForbidden {
		body, _ := ioutil.ReadAll(resp.Body)
		t.Fatalf("damSendTestRequest().StatusCode = %d, want %d\n body: %v", resp.StatusCode, http.StatusForbidden, string(body))
	}
}

func TestConfigReset_Hydra(t *testing.T) {
	s, _, _, h, iss, err := setupHydraTest(true)
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	cid := "c1"
	existingID := "00000000-0000-0000-0000-000000000000"
	newID := "00000000-0000-0000-0000-000000000002"

	h.ListClientsResp = []*hydraapi.Client{
		{ClientID: cid},
		{ClientID: existingID, Name: "foo"},
	}

	h.CreateClientResp = &hydraapi.Client{
		ClientID: newID,
	}

	h.UpdateClientResp = &hydraapi.Client{
		ClientID: existingID,
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
	path := strings.ReplaceAll(configResetPath, "{realm}", "master")
	header := http.Header{"Authorization": []string{"Bearer " + string(tok)}}
	resp := testhttp.SendTestRequest(t, s.Handler, http.MethodGet, path, q, nil, header)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("resp.StatusCode = %d, wants %d", resp.StatusCode, http.StatusOK)
	}

	if h.DeleteClientID != cid {
		t.Errorf("h.DeleteClientID = %s, wants %s", h.DeleteClientID, cid)
	}

	if h.UpdateClientReq.Name != "test_client" {
		t.Errorf("h.UpdateClientReq.Name = %s, wants test_client", h.UpdateClientReq.Name)
	}

	if h.CreateClientReq.Name != "test_client2" {
		t.Errorf("h.CreateClientReq.Name = %s, wants test_client2", h.CreateClientReq.Name)
	}
}
