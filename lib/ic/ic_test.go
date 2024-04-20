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
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"github.com/google/go-cmp/cmp/cmpopts" /* copybara-comment */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"github.com/go-openapi/strfmt" /* copybara-comment */
	"github.com/golang/protobuf/jsonpb" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/apis/hydraapi" /* copybara-comment: hydraapi */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/hydra" /* copybara-comment: hydra */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/kms/fakeencryption" /* copybara-comment: fakeencryption */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/kms/localsign" /* copybara-comment: localsign */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/persona" /* copybara-comment: persona */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakehydra" /* copybara-comment: fakehydra */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakeoidcissuer" /* copybara-comment: fakeoidcissuer */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/httptestclient" /* copybara-comment: httptestclient */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test" /* copybara-comment: test */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/testhttp" /* copybara-comment: testhttp */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/timeutil" /* copybara-comment: timeutil */

	glog "github.com/golang/glog" /* copybara-comment */
	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/ic/v1" /* copybara-comment: go_proto */
	cspb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/store/consents" /* copybara-comment: go_proto */
)

const (
	domain           = "example.com"
	hydraAdminURL    = "https://admin.hydra.example.com"
	hydraURL         = "https://hydra.example.com/"
	hydraURLInternal = "https://hydra.internal.example.com/"
	testClientID     = "00000000-0000-0000-0000-000000000000"
	testClientSecret = "00000000-0000-0000-0000-000000000001"
	useHydra         = true
	loginChallenge   = "lc-1234"
	consentChallenge = "cc-1234"
	idpName          = "idp"
	loginStateID     = "ls-1234"
	authTokenStateID = "ats-1234"
	LoginSubject     = "sub-1234"
	agree            = "y"
	deny             = "n"
)

var (
	defaultScope         = "openid offline ga4gh_passport_v1 profile email identities account_admin"
	defaultGrantTypes    = []string{"authorization_code"}
	defaultResponseTypes = []string{"token", "code", "id_token"}
)

func init() {
	err := os.Setenv("SERVICE_DOMAIN", domain)
	if err != nil {
		glog.Fatal("Setenv SERVICE_DOMAIN:", err)
	}
}

func TestHandlers(t *testing.T) {
	store := storage.NewMemoryStorage("ic-min", "testdata/config")
	server, err := fakeoidcissuer.New(hydraURL, &testkeys.PersonaBrokerKey, "dam-min", "testdata/config", false)
	if err != nil {
		t.Fatalf("fakeoidcissuer.New(%q, _, _) failed: %v", hydraURL, err)
	}
	crypt := fakeencryption.New()
	key := testkeys.Default
	signer := localsign.New(&key)

	opts := &Options{
		HTTPClient:     server.Client(),
		Domain:         domain,
		ServiceName:    "ic",
		AccountDomain:  domain,
		Store:          store,
		Encryption:     crypt,
		Signer:         signer,
		UseHydra:       useHydra,
		HydraAdminURL:  hydraAdminURL,
		HydraPublicURL: hydraURL,
		HydraSyncFreq:  time.Nanosecond,
	}
	s := NewService(opts)
	verifyService(t, s.domain, opts.Domain, "domain")
	verifyService(t, s.serviceName, opts.ServiceName, "serviceName")
	verifyService(t, s.accountDomain, opts.AccountDomain, "accountDomain")
	verifyService(t, strconv.FormatBool(s.useHydra), strconv.FormatBool(opts.UseHydra), "useHydra")
	verifyService(t, s.hydraAdminURL, opts.HydraAdminURL, "hydraAdminURL")
	verifyService(t, s.hydraPublicURL, opts.HydraPublicURL, "hydraPublicURL")

	tests := []test.HandlerTest{
		{
			Name:    "Get JWKS",
			Method:  "GET",
			Path:    "/visas/jwks",
			Persona: "non-admin",
			Output:  `{"keys":[{"use":"sig","kty":"RSA","kid":"testkeys-unknown","alg":"RS256","n":"U-Zmsn1SnacEYi5eXrBNT7hGxRunPSdGE-IWTe94Ch8n1hktdtQglKJ_JSvyyEzUm2V3xkwwDarNe8JXnMFWpHbY167PCrQ7tvpiKbg3hptQunubqD8NSkSy-wOMze0jvDpWhPiQaNObYbRHnSiPNXPjzD2_EKUWn0Ff9WG_MWU","e":"AQAB"}]}`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM groups",
			Method:  "GET",
			Path:    "/scim/v2/test/Groups",
			Persona: "admin",
			Output:  `{"Resources":[{"id":"admins","displayName":"System Administrators"},{"id":"allowlisted","displayName":"Allowlisted Users"},{"id":"auditors","displayName":"Auditors"},{"id":"lab","displayName":"Lab Members"}],"startIndex":1,"itemsPerPage":4,"totalResults":4,"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"]}`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM groups (paginate)",
			Method:  "GET",
			Path:    "/scim/v2/test/Groups",
			Params:  "startIndex=2&count=1",
			Persona: "admin",
			Output:  `^.*"startIndex":2,"itemsPerPage":1,"totalResults":4,.*`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM groups - filter displayName",
			Method:  "GET",
			Path:    "/scim/v2/test/Groups",
			Persona: "admin",
			Params:  `filter=displayName%20co%20"aud"`,
			Output:  `{"Resources":[{"id":"auditors","displayName":"Auditors"}],"startIndex":1,"itemsPerPage":1,"totalResults":1,"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"]}`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM groups - filter id",
			Method:  "GET",
			Path:    "/scim/v2/test/Groups",
			Persona: "admin",
			Params:  `filter=id%20co%20"l"`,
			Output:  `{"Resources":[{"id":"allowlisted","displayName":"Allowlisted Users"},{"id":"lab","displayName":"Lab Members"}],"startIndex":1,"itemsPerPage":2,"totalResults":2,"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"]}`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM groups (non-admin)",
			Method:  "GET",
			Path:    "/scim/v2/test/Groups",
			Persona: "non-admin",
			Output:  `^.*requires admin permission.*`,
			Status:  http.StatusUnauthorized,
		},
		{
			Name:    "Post SCIM groups",
			Method:  "POST",
			Path:    "/scim/v2/test/Groups",
			Persona: "admin",
			Output:  `*{"code":6,*}*`,
			Status:  http.StatusConflict,
		},
		{
			Name:    "Put SCIM groups",
			Method:  "PUT",
			Path:    "/scim/v2/test/Groups",
			Persona: "admin",
			Output:  `*not allowed*`,
			Status:  http.StatusBadRequest,
		},
		{
			Name:    "Patch SCIM groups",
			Method:  "PATCH",
			Path:    "/scim/v2/test/Groups",
			Persona: "admin",
			Output:  `*not allowed*`,
			Status:  http.StatusBadRequest,
		},
		{
			Name:    "Delete SCIM groups",
			Method:  "DELETE",
			Path:    "/scim/v2/test/Groups",
			Persona: "admin",
			Output:  `*not allowed*`,
			Status:  http.StatusBadRequest,
		},
		{
			Name:    "Get SCIM group (not exists)",
			Method:  "GET",
			Path:    "/scim/v2/test/Groups/group_1",
			Persona: "admin",
			Output:  `*{"code":5,"message":"*"}*`,
			Status:  http.StatusNotFound,
		},
		{
			Name:    "Post SCIM group",
			Method:  "POST",
			Path:    "/scim/v2/test/Groups/group_1",
			Persona: "admin",
			Input: `{
			  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
				"id": "group_1",
				"displayName": "Group 1"
			}`,
			Output: ``,
			Status: http.StatusOK,
		},
		{
			Name:    "Post SCIM group - with members",
			Method:  "POST",
			Path:    "/scim/v2/test/Groups/group_2",
			Persona: "admin",
			Input: `{
			  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
				"id": "group_2",
				"displayName": "Group 2",
				"members": [
				  {
						"type": "User",
						"display": "Dr. Joe",
						"value": "dr_joe@example.org"
					}, {
						"type": "User",
						"value": "someone@example.org"
					}, {
						"value": "Dr. Joe <dr_joe@home.example.org>"
					}
				]
			}`,
			Output: ``,
			Status: http.StatusOK,
		},
		{
			Name:    "Post SCIM group - invalid email address",
			Method:  "POST",
			Path:    "/scim/v2/test/Groups/group_3",
			Persona: "admin",
			Input: `{
			  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
				"id": "group_3",
				"displayName": "Group 3",
				"members": [{"value": "bad"}]
			}`,
			// Verifies that the escaped email address "bad" is included in the error message and the rich error info is there too.
			Output: `*"code":3*\"bad\"*"@type":"type.googleapis.com/google.rpc.ErrorInfo","metadata":{"index":"0"}*`,
			Status: http.StatusBadRequest,
		},
		{
			Name:    "Post SCIM group - invalid display name in display field",
			Method:  "POST",
			Path:    "/scim/v2/test/Groups/group_3",
			Persona: "admin",
			Input: `{
			  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
				"id": "group_3",
				"displayName": "Group 3",
				"members": [
				  {
						"display": "dr_joe@example.org",
						"value": "phishing@scam.com"
					}
				]
			}`,
			Output: `*"code":3*`,
			Status: http.StatusBadRequest,
		},
		{
			Name:    "Post SCIM group - invalid display name in email address",
			Method:  "POST",
			Path:    "/scim/v2/test/Groups/group_3",
			Persona: "admin",
			Input: `{
			  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
				"id": "group_3",
				"displayName": "Group 3",
				"members": [{"value": "dr_joe@example.org <phishing@scam.com>"}]
			}`,
			Output: `*"code":3*`,
			Status: http.StatusBadRequest,
		},
		{
			Name:    "Put SCIM group",
			Method:  "PUT",
			Path:    "/scim/v2/test/Groups/group_1",
			Persona: "admin",
			Input: `{
			  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
				"id": "group_1",
				"displayName": "Group 1",
				"members": [
				  {
						"type": "User",
						"value": "mary@example.org",
						"issuer": "https://example.org/oidc",
						"subject": "1234"
					},
					{
						"type": "User",
						"value": "Mary Poppins HQ <poppins@example.org>"
					}
				]
			}`,
			Output: ``,
			Status: http.StatusOK,
		},
		{
			Name:    "Get SCIM group (exists)",
			Method:  "GET",
			Path:    "/scim/v2/test/Groups/group_1",
			Persona: "admin",
			Output:  `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"id":"group_1","displayName":"Group 1","members":[{"type":"User","value":"mary@example.org","$ref":"mary@example.org","issuer":"https://example.org/oidc","subject":"1234"},{"type":"User","display":"Mary Poppins HQ","value":"poppins@example.org","$ref":"poppins@example.org"}]}`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Patch SCIM group",
			Method:  "PATCH",
			Path:    "/scim/v2/test/Groups/group_1",
			Persona: "admin",
			Input:   `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Group 1 Edit"},{"op":"add","path":"members","object":{"value":"Mary Poppins <marypoppins@example.org>"}},{"op":"remove","path":"members[$ref eq \"poppins@example.org\"]"}]}`,
			Output:  `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"id":"group_1","displayName":"Group 1 Edit","members":[{"type":"User","value":"mary@example.org","$ref":"mary@example.org","issuer":"https://example.org/oidc","subject":"1234"},{"type":"User","display":"Mary Poppins","value":"marypoppins@example.org","$ref":"marypoppins@example.org"}]}`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Patch SCIM group (bad email address)",
			Method:  "PATCH",
			Path:    "/scim/v2/test/Groups/group_1",
			Persona: "admin",
			Input:   `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add","path":"members","object":{"value":"mary0@example.org"}},{"op":"add","path":"members","object":{"value":"mary1@poppins@example.org"}}]}`,
			Output:  `*{"code":3,"message":"*"*"resourceName":"scim/groups/group_1/members/1/value"*"metadata":{"index":"1"}}*`,
			Status:  http.StatusBadRequest,
		},
		{
			Name:    "Patch SCIM group (missing remove member)",
			Method:  "PATCH",
			Path:    "/scim/v2/test/Groups/group_1",
			Persona: "admin",
			Input:   `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"members[$ref eq \"foo@example.org\"]"}]}`,
			Output:  `*{"code":3,"message":"*not a member*"}*`,
			Status:  http.StatusBadRequest,
		},
		{
			Name:    "Remove SCIM group",
			Method:  "DELETE",
			Path:    "/scim/v2/test/Groups/group_1",
			Persona: "admin",
			Output:  ``,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM group (after delete)",
			Method:  "GET",
			Path:    "/scim/v2/test/Groups/group_1",
			Persona: "admin",
			Output:  `*{"code":5,"message":"*"}*`,
			Status:  http.StatusNotFound,
		},
		{
			Name:    "Get SCIM users",
			Method:  "GET",
			Path:    "/scim/v2/test/Users",
			Persona: "admin",
			Output:  `{"Resources":[{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"admin","externalId":"admin","meta":{"resourceType":"User","created":"2019-06-22T13:29:50Z","lastModified":"2019-06-22T18:07:30Z","location":"https://example.com/scim/v2/test/Users/admin","version":"1"},"userName":"admin","name":{"formatted":"Administrator"},"displayName":"Administrator","active":true,"emails":[{"value":"admin@faculty.example.edu","$ref":"email//administrator"}]},{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"dr_joe_elixir","externalId":"dr_joe_elixir","meta":{"resourceType":"User","created":"2019-06-22T13:29:40Z","lastModified":"2019-06-22T18:07:20Z","location":"https://example.com/scim/v2/test/Users/dr_joe_elixir","version":"1"},"userName":"dr_joe_elixir","name":{"formatted":"Dr. Joe (ELIXIR)"},"displayName":"Dr. Joe (ELIXIR)","active":true,"emails":[{"value":"dr_joe@elixir.org","$ref":"email//dr_joe_elixir"},{"value":"dr_joe@faculty.example.edu","$ref":"email//dr_joe_faculty"}]},{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"non-admin","externalId":"non-admin","meta":{"resourceType":"User","created":"2019-06-22T13:29:59Z","lastModified":"2019-06-22T18:08:19Z","location":"https://example.com/scim/v2/test/Users/non-admin","version":"1"},"userName":"non-admin","name":{"formatted":"Non Administrator"},"displayName":"Non Administrator","active":true,"emails":[{"value":"non-admin@example.org","$ref":"email/persona/non-admin"},{"value":"non-admin-1@example.org","$ref":"email/persona/non-admin-1"}]},{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"someone-account","externalId":"someone-account","meta":{"resourceType":"User","created":"2019-06-22T13:29:36Z","lastModified":"2019-06-22T18:07:11Z","location":"https://example.com/scim/v2/test/Users/someone-account","version":"1"},"userName":"someone-account","name":{"formatted":"Someone at Somewhere","familyName":"Somewhere","givenName":"Someone","middleName":"at"},"displayName":"Someone Account","profileUrl":"https://example.org/users/someone","preferredLanguage":"en-CA","locale":"en-US","timezone":"America/New_York","active":true}],"startIndex":1,"itemsPerPage":4,"totalResults":4,"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"]}`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM users (paginate)",
			Method:  "GET",
			Path:    "/scim/v2/test/Users",
			Params:  "startIndex=3&count=1",
			Persona: "admin",
			Output:  `^.*"startIndex":3,"itemsPerPage":1,"totalResults":4,.*`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM users - filter active",
			Method:  "GET",
			Path:    "/scim/v2/test/Users",
			Persona: "admin",
			Params:  `filter=active%20eq%20"false"`,
			Output:  `^\{("Resources":\[\],)?"startIndex":1,"schemas":\["urn:ietf:params:scim:api:messages:2.0:ListResponse"\]}`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM users - filter displayName",
			Method:  "GET",
			Path:    "/scim/v2/test/Users",
			Persona: "admin",
			Params:  `filter=displayName%20co%20"administrator"`,
			Output:  `^.*"userName":"admin".*"userName":"non-admin".*"totalResults":2,.*`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM users - filter emails",
			Method:  "GET",
			Path:    "/scim/v2/test/Users",
			Persona: "admin",
			Params:  `filter=emails%20co%20"non-admin@example.org"`,
			Output:  `^.*"userName":"non-admin".*"totalResults":1,.*`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM users - filter externalId",
			Method:  "GET",
			Path:    "/scim/v2/test/Users",
			Persona: "admin",
			Params:  `filter=externalId%20co%20"admin"`,
			Output:  `^.*"userName":"admin".*"userName":"non-admin".*"totalResults":2,.*`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM users - filter id",
			Method:  "GET",
			Path:    "/scim/v2/test/Users",
			Persona: "admin",
			Params:  `filter=id%20co%20"admin"`,
			Output:  `^.*"userName":"admin".*"userName":"non-admin".*"totalResults":2,.*`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM users - filter preferred language",
			Method:  "GET",
			Path:    "/scim/v2/test/Users",
			Persona: "admin",
			Params:  `filter=preferredLanguage%20eq%20"en-CA"`,
			Output:  `^.*"userName":"someone-account".*"totalResults":1,.*`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM users - filter locale",
			Method:  "GET",
			Path:    "/scim/v2/test/Users",
			Persona: "admin",
			Params:  `filter=locale%20co%20"en-US"`,
			Output:  `^.*"userName":"someone-account".*"totalResults":1,.*`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM users - filter preferredLanguage",
			Method:  "GET",
			Path:    "/scim/v2/test/Users",
			Persona: "admin",
			Params:  `filter=preferredLanguage%20co%20"en"`,
			Output:  `^.*"userName":"someone-account".*"totalResults":1,.*`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM users - filter name.formatted",
			Method:  "GET",
			Path:    "/scim/v2/test/Users",
			Persona: "admin",
			Params:  `filter=name.formatted%20co%20"admin"`,
			Output:  `^.*"userName":"admin".*"userName":"non-admin".*"totalResults":2,.*`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM users - filter name.givenName",
			Method:  "GET",
			Path:    "/scim/v2/test/Users",
			Persona: "admin",
			Params:  `filter=name.givenName%20co%20"someone"`,
			Output:  `^.*"userName":"someone-account".*"totalResults":1,.*`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM users - filter name.familyName",
			Method:  "GET",
			Path:    "/scim/v2/test/Users",
			Persona: "admin",
			Params:  `filter=name.familyName%20sw%20"somewhere"`,
			Output:  `^.*"userName":"someone-account".*"totalResults":1,.*`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM users - filter name.middleName",
			Method:  "GET",
			Path:    "/scim/v2/test/Users",
			Persona: "admin",
			Params:  `filter=name.middleName%20ew%20"at"`,
			Output:  `^.*"userName":"someone-account".*"totalResults":1,.*`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM users - filter userName",
			Method:  "GET",
			Path:    "/scim/v2/test/Users",
			Persona: "admin",
			Params:  `filter=userName%20co%20"joe"`,
			Output:  `^.*"userName":"dr_joe_elixir".*"totalResults":1,.*`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM users - filter timezone",
			Method:  "GET",
			Path:    "/scim/v2/test/Users",
			Persona: "admin",
			Params:  `filter=timezone%20co%20"america"`,
			Output:  `^.*"userName":"someone-account".*"totalResults":1,.*`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM users - filter OR clause",
			Method:  "GET",
			Path:    "/scim/v2/test/Users",
			Persona: "admin",
			Params:  `filter=displayName%20co%20"administrator"%20or%20userName%20co%20"joe"`,
			Output:  `^.*"userName":"admin".*"userName":"dr_joe_elixir".*"userName":"non-admin".*"totalResults":3,.*`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM users - filter CNF clause match",
			Method:  "GET",
			Path:    "/scim/v2/test/Users",
			Persona: "admin",
			Params:  `filter=%28displayName%20co%20%22administrator%22%20or%20userName%20co%20%22joe%22%29%20and%20active%20eq%20%22true%22`,
			Output:  `^.*"userName":"admin".*"userName":"dr_joe_elixir".*"userName":"non-admin".*"totalResults":3,.*`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM users - filter CNF clause no match",
			Method:  "GET",
			Path:    "/scim/v2/test/Users",
			Persona: "admin",
			Params:  `filter=%28displayName%20co%20%22administrator%22%20or%20userName%20co%20%22joe%22%29%20and%20active%20ne%20%22true%22`,
			Output:  `{"startIndex":1,"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"]}`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM users (non-admin)",
			Method:  "GET",
			Path:    "/scim/v2/test/Users",
			Persona: "non-admin",
			Scope:   persona.AccountScope,
			Output:  `^.*requires admin permission.*`,
			Status:  http.StatusUnauthorized,
		},
		{
			Name:    "Get SCIM me",
			Method:  "GET",
			Path:    "/scim/v2/test/Me",
			Persona: "non-admin",
			Scope:   persona.AccountScope,
			Output:  `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"non-admin","externalId":"non-admin","meta":{"resourceType":"User","created":"2019-06-22T13:29:59Z","lastModified":"2019-06-22T18:08:19Z","location":"https://example.com/scim/v2/test/Users/non-admin","version":"1"},"userName":"non-admin","name":{"formatted":"Non Administrator"},"displayName":"Non Administrator","active":true,"emails":[{"value":"non-admin@example.org","$ref":"email/persona/non-admin"},{"value":"non-admin-1@example.org","$ref":"email/persona/non-admin-1"}]}`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM me (default scope)",
			Method:  "GET",
			Path:    "/scim/v2/test/Me",
			Persona: "non-admin",
			Output:  `^.*urn:ietf:params:scim:schemas:core:2.0:User.*`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Patch SCIM me (default scope)",
			Method:  "PATCH",
			Path:    "/scim/v2/test/Me",
			Persona: "non-admin",
			Input:   `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"name.formatted","value":"Non-Administrator"},{"op":"replace","path":"active","value":"false"}]}`,
			Output:  `^.*account_admin.*`,
			Status:  http.StatusUnauthorized,
		},
		{
			Name:    "Patch SCIM me (bad photo)",
			Method:  "PATCH",
			Path:    "/scim/v2/test/Me",
			Persona: "non-admin",
			Scope:   persona.AccountScope,
			Input:   `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"photos[type eq \"thumbnail\"].value","value":"I am a teapot"}]}`,
			Output:  `^.*invalid photo.*"type.googleapis.com/google.rpc.ErrorInfo","metadata":{"index":"0"}.*`,
			Status:  http.StatusBadRequest,
		},
		{
			Name:    "Patch SCIM me (update photo)",
			Method:  "PATCH",
			Path:    "/scim/v2/test/Me",
			Persona: "non-admin",
			Scope:   persona.AccountScope,
			Input:   `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"photos[type eq \"thumbnail\"].value","value":"https://my.example.org/photos/me.jpeg"}]}`,
			Output:  `^.*"photos":\[\{"primary":true,"value":"https://my.example.org/photos/me.jpeg"\}\]`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Patch SCIM me (set primary email)",
			Method:  "PATCH",
			Path:    "/scim/v2/test/Me",
			Persona: "non-admin",
			Scope:   persona.AccountScope,
			Input:   `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"emails[$ref eq \"email/persona/non-admin\"].primary","value":"true"}]}`,
			Output:  `^.*"primary":true,"value":"non-admin@example.org".*`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Patch SCIM me (remove primary email)",
			Method:  "PATCH",
			Path:    "/scim/v2/test/Me",
			Persona: "non-admin",
			Scope:   persona.AccountScope,
			Input:   `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"emails[primary eq \"true\"].primary"}]}`,
			Output:  `^.*"emails":\[\{"value":"non-admin@example.org","\$ref":"email/persona/non-admin"\},\{"value":"non-admin-1@example.org","\$ref":"email/persona/non-admin-1"\}\].*`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Patch SCIM me (multiple ops)",
			Method:  "PATCH",
			Path:    "/scim/v2/test/Me",
			Persona: "non-admin",
			Scope:   persona.AccountScope,
			Input:   `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"name.formatted","value":"Non-Administrator"},{"op":"replace","path":"active","value":"false"}]}`,
			Output:  `^\{"schemas":\["urn:ietf:params:scim:schemas:core:2.0:User"\],"id":"non-admin","externalId":"non-admin","meta":\{"resourceType":"User","created":"2019-06-22T13:29:59Z","lastModified":"....-..-..T..:..:..Z","location":"https://example.com/scim/v2/test/Users/non-admin","version":"4"\},"userName":"non-admin","name":\{"formatted":"Non-Administrator"\},"displayName":"Non Administrator","emails":\[\{"value":"non-admin@example.org","\$ref":"email/persona/non-admin"\},\{"value":"non-admin-1@example.org","\$ref":"email/persona/non-admin-1"\}\],"photos":\[\{"primary":true,"value":"https://my.example.org/photos/me.jpeg"\}\]\}`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Patch SCIM active (admin)",
			Method:  "PATCH",
			Path:    "/scim/v2/test/Users/non-admin",
			Persona: "admin",
			Input:   `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":"true"},{"op":"replace","path":"displayName","value":"Updated Non Admin"},{"op":"replace","path":"profileUrl","value":"https://example.org/users/non-admin"},{"op":"replace","path":"preferredLanguage","value":"fr-FR"},{"op":"replace","path":"locale","value":"fr-CA"},{"op":"replace","path":"timezone","value":"America/Montreal"}]}`,
			Output:  `^\{"schemas":\["urn:ietf:params:scim:schemas:core:2.0:User"\],"id":"non-admin","externalId":"non-admin","meta":\{"resourceType":"User","created":"2019-06-22T13:29:59Z","lastModified":"20..-..-..T..:..:..Z","location":"https://example.com/scim/v2/test/Users/non-admin","version":"5"},"userName":"non-admin","name":\{"formatted":"Non-Administrator"\},"displayName":"Updated Non Admin","profileUrl":"https://example.org/users/non-admin","preferredLanguage":"fr-FR","locale":"fr-CA","timezone":"America/Montreal","active":true,"emails":\[\{"value":"non-admin@example.org","\$ref":"email/persona/non-admin"\},\{"value":"non-admin-1@example.org","\$ref":"email/persona/non-admin-1"\}\],"photos":\[\{"primary":true,"value":"https://my.example.org/photos/me.jpeg"\}\]\}`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Unlink connected account (default scope)",
			Method:  "PATCH",
			Path:    "/scim/v2/test/Users/non-admin",
			Persona: "non-admin",
			Input:   `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"emails[$ref eq \"email/persona/non-admin-1\"]","value":"foo"}]}`,
			Output:  `^.*account_admin.*`,
			Status:  http.StatusUnauthorized,
		},
		{
			Name:    "Unlink connected account",
			Method:  "PATCH",
			Path:    "/scim/v2/test/Users/non-admin",
			Persona: "non-admin",
			Scope:   persona.AccountScope,
			Input:   `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"emails[$ref eq \"email/persona/non-admin-1\"]"}]}`,
			Output:  `^.*"emails":\[\{"value":"non-admin@example.org","\$ref":"email/persona/non-admin"\}\].*`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Unlink connected account (invalid remove last)",
			Method:  "PATCH",
			Path:    "/scim/v2/test/Users/non-admin",
			Persona: "non-admin",
			Scope:   persona.AccountScope,
			Input:   `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"emails[value eq \"non-admin@example.org\"]"}]}`,
			Output:  `^.*cannot unlink the only email address.*`,
			Status:  http.StatusBadRequest,
		},
		{
			Name:    "Delete SCIM me (default scope)",
			Method:  "DELETE",
			Path:    "/scim/v2/test/Me",
			Persona: "non-admin",
			Output:  `^.*account_admin.*`,
			Status:  http.StatusUnauthorized,
		},
		{
			Name:    "Delete SCIM me",
			Method:  "DELETE",
			Path:    "/scim/v2/test/Me",
			Persona: "non-admin",
			Scope:   persona.AccountScope,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM me (after account deleted)",
			Method:  "GET",
			Path:    "/scim/v2/test/Me",
			Persona: "non-admin",
			Scope:   persona.AccountScope,
			Output:  `*{"code":5,"message":"*"}*`,
			Status:  http.StatusNotFound,
		},
		{
			Name:    "Get SCIM account (admin)",
			Method:  "GET",
			Path:    "/scim/v2/test/Users/dr_joe_elixir",
			Persona: "admin",
			Output:  `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"dr_joe_elixir","externalId":"dr_joe_elixir","meta":{"resourceType":"User","created":"2019-06-22T13:29:40Z","lastModified":"2019-06-22T18:07:20Z","location":"https://example.com/scim/v2/test/Users/dr_joe_elixir","version":"1"},"userName":"dr_joe_elixir","name":{"formatted":"Dr. Joe (ELIXIR)"},"displayName":"Dr. Joe (ELIXIR)","active":true,"emails":[{"value":"dr_joe@elixir.org","$ref":"email//dr_joe_elixir"},{"value":"dr_joe@faculty.example.edu","$ref":"email//dr_joe_faculty"}],"groups":[{"display":"Allowlisted Users","value":"allowlisted","$ref":"group/allowlisted/dr_joe@elixir.org"},{"display":"Allowlisted Users","value":"allowlisted","$ref":"group/allowlisted/dr_joe@faculty.example.edu"},{"display":"Lab Members","value":"lab","$ref":"group/lab/dr_joe@elixir.org"}]}`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM account",
			Method:  "GET",
			Path:    "/scim/v2/test/Users/dr_joe_elixir",
			Persona: "dr_joe_elixir",
			Scope:   persona.AccountScope,
			Output:  `*{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"dr_joe_elixir","externalId":"dr_joe_elixir","meta":{"resourceType":"User","created":"2019-06-22T13:29:40Z","lastModified":"2019-06-22T18:07:20Z","location":"https://example.com/scim/v2/test/Users/dr_joe_elixir","version":"1"},"userName":"dr_joe_elixir","name":{"formatted":"Dr. Joe (ELIXIR)"},"displayName":"Dr. Joe (ELIXIR)","active":true,"emails":[*],"groups":[*]}*`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM account (default scope)",
			Method:  "GET",
			Path:    "/scim/v2/test/Users/dr_joe_elixir",
			Persona: "dr_joe_elixir",
			Output:  `*urn:ietf:params:scim:schemas:core:2.0:User*"groups"*"allowlisted"*`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Patch SCIM account",
			Method:  "PATCH",
			Path:    "/scim/v2/test/Users/dr_joe_elixir",
			Persona: "dr_joe_elixir",
			Scope:   persona.AccountScope,
			Input:   `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"name.formatted","value":"The good doc"},{"op":"replace","path":"name.givenName","value":"Joesph"},{"op":"replace","path":"name.familyName","value":"Doctor"}]}`,
			Output:  `*{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"dr_joe_elixir","externalId":"dr_joe_elixir","meta":{"resourceType":"User","created":"2019-06-22T13:29:40Z","lastModified":"2019-06-22T18:07:20Z","location":"https://example.com/scim/v2/test/Users/dr_joe_elixir","version":"1"},"userName":"dr_joe_elixir","name":{"formatted":"The good doc","familyName":"Doctor","givenName":"Joesph"},"displayName":"Dr. Joe (ELIXIR)","active":true,"emails":[*]}*`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Patch SCIM account (default scope)",
			Method:  "PATCH",
			Path:    "/scim/v2/test/Users/dr_joe_elixir",
			Persona: "dr_joe_elixir",
			Input:   `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"name.formatted","value":"The good doc"},{"op":"replace","path":"name.givenName","value":"Joesph"},{"op":"replace","path":"name.familyName","value":"Doctor"}]}`,
			Output:  `^.*account_admin.*`,
			Status:  http.StatusUnauthorized,
		},
		{
			Name:    "Delete SCIM account (default scope)",
			Method:  "DELETE",
			Path:    "/scim/v2/test/Users/dr_joe_elixir",
			Persona: "dr_joe_elixir",
			Output:  `^.*account_admin.*`,
			Status:  http.StatusUnauthorized,
		},
		{
			Name:    "Delete SCIM account",
			Method:  "DELETE",
			Path:    "/scim/v2/test/Users/dr_joe_elixir",
			Persona: "dr_joe_elixir",
			Scope:   persona.AccountScope,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get deleted SCIM account",
			Method:  "GET",
			Path:    "/scim/v2/test/Users/dr_joe_elixir",
			Persona: "dr_joe_elixir",
			Scope:   persona.AccountScope,
			Output:  `*{"code":5,"message":"*"}*`,
			Status:  http.StatusNotFound,
		},
		{
			Name:    "Get deleted SCIM account (admin)",
			Method:  "GET",
			Path:    "/scim/v2/test/Users/dr_joe_elixir",
			Persona: "admin",
			Output:  `^.*dr_joe_elixir.*`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Undelete SCIM account (admin)",
			Method:  "PATCH",
			Path:    "/scim/v2/test/Users/dr_joe_elixir",
			Persona: "admin",
			Input:   `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":"true"}]}`,
			Output:  `^.*dr_joe_elixir.*"active":true.*`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Link SCIM account error (missing X-Link-Authorization)",
			Method:  "PATCH",
			Path:    "/scim/v2/test/Me",
			Persona: "dr_joe_elixir",
			Scope:   persona.LinkScope,
			Input:   `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add","path":"emails","value":"X-Link-Authorization"}]}`,
			Output:  `^.*X-Link-Authorization.*`,
			Status:  http.StatusBadRequest,
		},
		{
			Name:        "Link SCIM account error (missing primary link scope)",
			Method:      "PATCH",
			Path:        "/scim/v2/test/Me",
			Persona:     "dr_joe_elixir",
			Scope:       persona.AccountScope,
			LinkPersona: "admin",
			LinkScope:   persona.LinkScope,
			Input:       `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add","path":"emails","value":"X-Link-Authorization"}]}`,
			Output:      `*{"code":3,"message":"bearer token unauthorized for scope \"link\""*scim/user/profile/emails*}*`,
			Status:      http.StatusBadRequest,
		},
		{
			Name:        "Link SCIM account error (missing secondary link scope)",
			Method:      "PATCH",
			Path:        "/scim/v2/test/Me",
			Persona:     "dr_joe_elixir",
			Scope:       persona.LinkScope,
			LinkPersona: "admin",
			LinkScope:   persona.AccountScope,
			Input:       `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add","path":"emails","value":"X-Link-Authorization"}]}`,
			Output:      `*link* scope*`,
			Status:      http.StatusUnauthorized,
		},
		{
			Name:        "Link SCIM account",
			Method:      "PATCH",
			Path:        "/scim/v2/test/Me",
			Persona:     "dr_joe_elixir",
			Scope:       persona.LinkScope,
			LinkPersona: "admin",
			LinkScope:   persona.LinkScope,
			Input:       `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add","path":"emails","value":"X-Link-Authorization"}]}`,
			Output:      `^.*dr_joe_elixir.*"active":true.*"admin@faculty.example.edu".*`,
			Status:      http.StatusOK,
		},
	}
	test.HandlerTests(t, s.Handler, tests, hydraURL, server.Config())
}

func createTestToken(t *testing.T, s *Service, iss *fakeoidcissuer.Server, id *ga4gh.Identity, scope, jti string) string {
	id.Scope = scope
	id.Realm = "test"
	id.IssuedAt = time.Now().Unix()
	id.Expiry = time.Now().Add(time.Hour).Unix()
	id.Audiences = ga4gh.NewAudience(testClientID)
	id.ID = jti
	tok, err := iss.Sign(map[string]string{}, id)
	if err != nil {
		t.Fatalf("creating test token: %v", err)
	}

	tokenMetadata := &pb.TokenMetadata{
		TokenType:        "refresh",
		IssuedAt:         id.IssuedAt,
		Scope:            id.Scope,
		IdentityProvider: id.IdentityProvider,
	}
	s.store.Write(storage.TokensDatatype, "test", id.Subject, id.ID, storage.LatestRev, tokenMetadata, nil)
	return tok
}

func TestAdminHandlers(t *testing.T) {
	store := storage.NewMemoryStorage("ic-min", "testdata/config")
	server, err := fakeoidcissuer.New(hydraURL, &testkeys.PersonaBrokerKey, "dam-min", "testdata/config", false)
	if err != nil {
		t.Fatalf("fakeoidcissuer.New(%q, _, _) failed: %v", hydraURL, err)
	}

	s := NewService(&Options{
		HTTPClient:     server.Client(),
		Domain:         domain,
		ServiceName:    "ic",
		AccountDomain:  domain,
		Store:          store,
		Encryption:     fakeencryption.New(),
		UseHydra:       useHydra,
		HydraAdminURL:  hydraAdminURL,
		HydraPublicURL: hydraURL,
		HydraSyncFreq:  time.Nanosecond,
	})
	tests := []test.HandlerTest{
		{
			Name:    "List all tokens of all users as a non-admin",
			Method:  "GET",
			Path:    "/identity/v1alpha/test/admin/tokens",
			Persona: "non-admin",
			Output:  `^.*requires admin permission	*`,
			Status:  http.StatusUnauthorized,
		},
		{
			Name:    "List all tokens of all users as an admin",
			Method:  "GET",
			Path:    "/identity/v1alpha/test/admin/tokens",
			Persona: "admin",
			Output:  `{"tokensMetadata":{"dr_joe_elixir/123-456":{"tokenType":"refresh","issuedAt":"1560970669","scope":"ga4gh_passport_v1 identities profiles openid","identityProvider":"elixir"},"someone-account/1a2-3b4":{"tokenType":"refresh","issuedAt":"1560970669","scope":"ga4gh_passport_v1 openid","identityProvider":"google"}}}`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Delete all tokens of all users as a non-admin",
			Method:  "DELETE",
			Path:    "/identity/v1alpha/test/admin/tokens",
			Persona: "non-admin",
			Output:  `^.*requires admin permission	*`,
			Status:  http.StatusUnauthorized,
		},
		{
			Name:    "Delete all tokens of all users as an admin",
			Method:  "DELETE",
			Path:    "/identity/v1alpha/test/admin/tokens",
			Persona: "admin",
			Output:  ``,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get deleted tokens of all users as an admin",
			Method:  "GET",
			Path:    "/identity/v1alpha/test/admin/tokens",
			Persona: "admin",
			Output:  `{}`,
			Status:  http.StatusOK,
		},
		{
			Method:  "PUT",
			Path:    "/identity/v1alpha/master/clients:sync",
			Persona: "non-admin",
			Output:  `^.*not allowed`,
			Status:  http.StatusBadRequest,
		},
		{
			Method:       "PUT",
			Path:         "/identity/v1alpha/master/clients:sync",
			Persona:      "non-admin",
			ClientID:     "bad",
			ClientSecret: "worse",
			Output:       `^.*unrecognized`,
			Status:       http.StatusUnauthorized,
		},
		{
			Method:  "PATCH",
			Path:    "/identity/v1alpha/master/clients:sync",
			Persona: "non-admin",
			Output:  `^.*not allowed`,
			Status:  http.StatusBadRequest,
		},
		{
			Method:  "DELETE",
			Path:    "/identity/v1alpha/master/clients:sync",
			Persona: "non-admin",
			Output:  `^.*not allowed`,
			Status:  http.StatusBadRequest,
		},
		{
			Method:  "GET",
			Path:    "/identity/v1alpha/test/clients:sync",
			Persona: "admin",
			Output:  `^.*client sync only allow on master realm`,
			Status:  http.StatusForbidden,
		},
		{
			Method:  "POST",
			Path:    "/identity/v1alpha/test/clients:sync",
			Persona: "admin",
			Output:  `^.*client sync only allow on master realm`,
			Status:  http.StatusForbidden,
		},
	}
	test.HandlerTests(t, s.Handler, tests, hydraURL, server.Config())
}

func verifyService(t *testing.T, got, want, field string) {
	if got != want {
		t.Errorf("service %q mismatch: got %q, want %q", field, got, want)
	}
}

func TestAddLinkedIdentities(t *testing.T) {
	subject := "111@a.com"
	issuer := "https://example.com/visas"
	subjectInIdp := "222"
	emailInIdp := "222@idp.com"
	idp := "idp"
	idpIss := "https://idp.com/oidc"

	id := &ga4gh.Identity{
		Subject:  subject,
		Issuer:   issuer,
		VisaJWTs: []string{},
		Expiry:   time.Now().Unix() + 10000,
	}

	link := &cpb.ConnectedAccount{
		Provider: idp,
		Properties: &cpb.AccountProperties{
			Subject: subjectInIdp,
			Email:   emailInIdp,
		},
	}

	server, err := fakeoidcissuer.New(hydraURL, &testkeys.PersonaBrokerKey, "dam-min", "testdata/config", false)
	if err != nil {
		t.Fatalf("fakeoidcissuer.New(%q, _, _) failed: %v", hydraURL, err)
	}

	store := storage.NewMemoryStorage("ic-min", "testdata/config")
	s := NewService(&Options{
		HTTPClient:     server.Client(),
		Domain:         domain,
		ServiceName:    "ic",
		AccountDomain:  domain,
		Store:          store,
		Encryption:     fakeencryption.New(),
		Signer:         localsign.New(&testkeys.Default),
		UseHydra:       useHydra,
		HydraAdminURL:  hydraAdminURL,
		HydraPublicURL: hydraURL,
	})
	cfg, err := s.loadConfig(nil, storage.DefaultRealm)
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}
	cfg.IdentityProviders = map[string]*cpb.IdentityProvider{
		idp: &cpb.IdentityProvider{Issuer: idpIss},
	}

	err = s.addLinkedIdentities(context.Background(), id, link, cfg)
	if err != nil {
		t.Fatalf("s.addLinkedIdentities(_) failed: %v", err)
	}

	if len(id.VisaJWTs) != 1 {
		t.Fatalf("len(id.VisaJWTs), want 1, got %d", len(id.VisaJWTs))
	}

	v, err := ga4gh.NewVisaFromJWT(ga4gh.VisaJWT(id.VisaJWTs[0]))
	if err != nil {
		t.Fatalf("ga4gh.NewVisaFromJWT(_) failed: %v", err)
	}

	got := v.Data()

	wantIdentities := []string{
		linkedIdentityValue(emailInIdp, idpIss),
		linkedIdentityValue(subjectInIdp, idpIss),
	}

	want := &ga4gh.VisaData{
		StdClaims: ga4gh.StdClaims{
			Subject:   subject,
			Issuer:    issuer,
			IssuedAt:  got.IssuedAt,
			ExpiresAt: got.ExpiresAt,
		},
		Assertion: ga4gh.Assertion{
			Type:     ga4gh.LinkedIdentities,
			Asserted: got.Assertion.Asserted,
			Value:    ga4gh.Value(strings.Join(wantIdentities, ";")),
			Source:   ga4gh.Source(issuer),
		},
	}

	if diff := cmp.Diff(want, got); len(diff) != 0 {
		t.Fatalf("v.Data() returned diff (-want +got):\n%s", diff)
	}

	if got.ExpiresAt-time.Now().Unix() > 3600 {
		t.Errorf("got.ExpiresAt = now + %v seconds, want less than a hour", (got.ExpiresAt - time.Now().Unix()))
	}

	jku := "https://example.com/visas/jwks"
	if v.JKU() != jku {
		t.Errorf("v.JKU() = %s, wants %s", v.JKU(), jku)
	}
}

func setupHydraTest() (*Service, *pb.IcConfig, *pb.IcSecrets, *fakehydra.Server, *persona.Server, error) {
	store := storage.NewMemoryStorage("ic-min", "testdata/config")
	server, err := persona.NewBroker(hydraURL, &testkeys.PersonaBrokerKey, "dam-min", "testdata/config", false)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	h := fakehydra.New(server.Handler)

	crypt := fakeencryption.New()
	s := NewService(&Options{
		HTTPClient:     httptestclient.New(server.Handler),
		Domain:         domain,
		ServiceName:    "ic-min",
		AccountDomain:  domain,
		Store:          store,
		Encryption:     crypt,
		UseHydra:       useHydra,
		HydraAdminURL:  hydraAdminURL,
		HydraPublicURL: hydraURL,
		HydraSyncFreq:  time.Nanosecond,
	})

	cfg, err := s.loadConfig(nil, storage.DefaultRealm)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	sec, err := s.loadSecrets(nil)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	return s, cfg, sec, h, server, nil
}

func TestHydraLogin_LoginPage_Hydra(t *testing.T) {
	s, _, _, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	h.GetLoginRequestResp = &hydraapi.LoginRequest{
		RequestURL:     hydraURL + "auth",
		RequestedScope: []string{"openid"},
	}

	w := httptest.NewRecorder()
	params := fmt.Sprintf("?login_challenge=%s", loginChallenge)
	u := "https://ic.example.com" + hydraLoginPath + params
	r := httptest.NewRequest(http.MethodGet, u, nil)

	s.Handler.ServeHTTP(w, r)

	resp := w.Result()

	// return login page if not login hint included
	if resp.StatusCode != http.StatusOK {
		t.Errorf("resp.StatusCode wants %d, got %d", http.StatusOK, resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "text/html" {
		t.Errorf("contentType = %s want text/html", contentType)
	}
}

func TestHydraLogin_Hydra_Error(t *testing.T) {
	s, _, _, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	h.GetLoginRequestErr = &hydraapi.GenericError{Code: http.StatusServiceUnavailable}

	w := httptest.NewRecorder()
	params := fmt.Sprintf("?login_challenge=%s", loginChallenge)
	u := "https://ic.example.com" + hydraLoginPath + params
	r := httptest.NewRequest(http.MethodGet, u, nil)

	s.Handler.ServeHTTP(w, r)

	resp := w.Result()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("resp.StatusCode wants %d, got %d", http.StatusServiceUnavailable, resp.StatusCode)
	}
}

func TestHydraLogin_LoginHint_Hydra(t *testing.T) {
	s, cfg, _, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	h.GetLoginRequestResp = &hydraapi.LoginRequest{
		RequestURL:     hydraURL + "auth?login_hint=" + idpName + ":foo@bar.com",
		RequestedScope: []string{"openid"},
	}

	w := httptest.NewRecorder()
	params := fmt.Sprintf("?login_challenge=%s", loginChallenge)
	u := "https://ic.example.com" + hydraLoginPath + params
	r := httptest.NewRequest(http.MethodGet, u, nil)

	s.Handler.ServeHTTP(w, r)

	resp := w.Result()

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("resp.StatusCode wants %d, got %d", http.StatusSeeOther, resp.StatusCode)
	}

	idpc := cfg.IdentityProviders[idpName]

	l := resp.Header.Get("Location")
	loc, err := url.Parse(l)
	if err != nil {
		t.Fatalf("url.Parse(%s) failed", l)
	}

	a, err := url.Parse(idpc.AuthorizeUrl)
	if err != nil {
		t.Fatalf("url.Parse(%s) failed", idpc.AuthorizeUrl)
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
	if q.Get("response_type") != idpc.ResponseType {
		t.Errorf("response_type wants %s, got %s", idpc.ResponseType, q.Get("response_type"))
	}
	wantLoginHint := "foo@bar.com"
	if q.Get("login_hint") != wantLoginHint {
		t.Errorf("login_hint = %s wants %s", q.Get("login_hint"), wantLoginHint)
	}

	state := q.Get("state")
	var loginState cpb.LoginState
	err = s.store.Read(storage.LoginStateDatatype, storage.DefaultRealm, storage.DefaultUser, state, storage.LatestRev, &loginState)
	if err != nil {
		t.Fatalf("read login state failed, %v", err)
		return
	}

	if loginState.LoginChallenge != loginChallenge {
		t.Errorf("state.LoginChallenge wants %s got %s", loginChallenge, loginState.LoginChallenge)
	}
	if loginState.Provider != idpName {
		t.Errorf("state.Provider wants %s got %s", idpName, loginState.Provider)
	}
}

func sendLogin(s *Service, idp string) *http.Response {
	w := httptest.NewRecorder()
	params := fmt.Sprintf("?scope=openid&login_challenge=%s", loginChallenge)
	u := "https://ic.example.com" + loginPath + params
	u = strings.ReplaceAll(u, "{realm}", storage.DefaultRealm)
	u = strings.ReplaceAll(u, "{name}", idp)
	r := httptest.NewRequest(http.MethodGet, u, nil)

	s.Handler.ServeHTTP(w, r)

	return w.Result()
}

func TestLogin_Hydra(t *testing.T) {
	s, cfg, _, _, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	resp := sendLogin(s, idpName)

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("resp.StatusCode wants %d, got %d", http.StatusSeeOther, resp.StatusCode)
	}

	idpc := cfg.IdentityProviders[idpName]

	l := resp.Header.Get("Location")
	loc, err := url.Parse(l)
	if err != nil {
		t.Fatalf("url.Parse(%s) failed", l)
	}

	a, err := url.Parse(idpc.AuthorizeUrl)
	if err != nil {
		t.Fatalf("url.Parse(%s) failed", idpc.AuthorizeUrl)
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
	if q.Get("response_type") != idpc.ResponseType {
		t.Errorf("response_type wants %s, got %s", idpc.ResponseType, q.Get("response_type"))
	}

	state := q.Get("state")
	var loginState cpb.LoginState
	err = s.store.Read(storage.LoginStateDatatype, storage.DefaultRealm, storage.DefaultUser, state, storage.LatestRev, &loginState)
	if err != nil {
		t.Fatalf("read login state failed, %v", err)
		return
	}

	if loginState.LoginChallenge != loginChallenge {
		t.Errorf("state.LoginChallenge wants %s got %s", loginChallenge, loginState.LoginChallenge)
	}
	if loginState.Provider != idpName {
		t.Errorf("state.Provider wants %s got %s", idpName, loginState.Provider)
	}
}

func TestLogin_Hydra_invalid_idp_Error(t *testing.T) {
	s, _, _, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	h.RejectLoginResp = &hydraapi.RequestHandlerResponse{RedirectTo: hydraURL}

	resp := sendLogin(s, "invalid")

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("StatusCode = %d, wants %d", resp.StatusCode, http.StatusSeeOther)
	}

	if h.RejectLoginReq.Code != http.StatusNotFound {
		t.Errorf("RejectLoginReq.Code = %d, wants %d", h.RejectLoginReq.Code, http.StatusNotFound)
	}
}

func sendAcceptLogin(s *Service, cfg *pb.IcConfig, h *fakehydra.Server, code, state, errName, errDesc string) (*http.Response, error) {
	// Ensure login state exists before request.
	login := &cpb.LoginState{
		Provider:       idpName,
		Realm:          storage.DefaultRealm,
		LoginChallenge: loginChallenge,
	}

	err := s.store.Write(storage.LoginStateDatatype, storage.DefaultRealm, storage.DefaultUser, loginStateID, storage.LatestRev, login, nil)
	if err != nil {
		return nil, err
	}

	// Clear fakehydra server and set reject response.
	h.Clear()
	h.RejectLoginResp = &hydraapi.RequestHandlerResponse{RedirectTo: hydraURL}

	// Send Request.
	p := "?code=%s&state=%s&error=%s&error_description=%s"
	query := fmt.Sprintf(p, url.QueryEscape(code), url.QueryEscape(state), url.QueryEscape(errName), url.QueryEscape(errDesc))
	u := "https://" + domain + acceptLoginPath + query
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, u, nil)
	s.Handler.ServeHTTP(w, r)

	return w.Result(), nil
}

func TestAcceptLogin_Hydra_ToFinishLogin(t *testing.T) {
	s, cfg, _, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	const (
		authCode = "non-admin," + idpName
	)

	tests := []struct {
		name  string
		code  string
		state string
	}{
		{
			name:  "Success Login",
			code:  authCode,
			state: loginStateID,
		},
		{
			name:  "invalid auth_code: we don't know if code invalid at this step",
			code:  "invalid",
			state: loginStateID,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := sendAcceptLogin(s, cfg, h, tc.code, tc.state, "", "")
			if err != nil {
				t.Fatalf("sendAcceptLogin(s, cfg, h, %s, %s, '', '') failed: %v", tc.code, tc.state, err)
			}

			if h.AcceptLoginReq != nil {
				t.Errorf("AcceptLoginReq wants nil got %v", h.AcceptLoginReq)
			}
			if h.RejectLoginReq != nil {
				t.Errorf("RejectLoginReq wants nil got %v", h.RejectLoginReq)
			}

			if resp.StatusCode != http.StatusSeeOther {
				t.Errorf("statusCode wants %d got %d", http.StatusSeeOther, resp.StatusCode)
			}

			l := resp.Header.Get("Location")
			loc, err := url.Parse(l)
			if err != nil {
				t.Fatalf("url.Parse(%s) failed: %v", l, err)
			}

			if loc.Path != "/identity/v1alpha/master/loggedin/idp" {
				t.Errorf("loc.Path wants /identity/v1alpha/master/loggedin/idp got %s", loc.Path)
			}
		})
	}
}

func TestAcceptLogin_Hydra_Reject(t *testing.T) {
	s, cfg, _, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	const (
		errName = "idpErr"
		errDesc = "Error message from upstream idp"
	)

	resp, err := sendAcceptLogin(s, cfg, h, "", loginStateID, errName, errDesc)
	if err != nil {
		t.Fatalf("sendAcceptLogin(s, cfg, sec, h, '', %s, %s, %s) failed: %v", hydra.StateIDKey, errName, errDesc, err)
	}

	if h.RejectLoginReq.Name != errName {
		t.Errorf("RejectLoginReq.Name wants %s got %s", errName, h.RejectLoginReq.Name)
	}
	wantDesc := "rpc error: code = Unauthenticated desc = " + errDesc
	if h.RejectLoginReq.Description != wantDesc {
		t.Errorf("RejectLoginReq.Description wants %s got %s", wantDesc, h.RejectLoginReq.Description)
	}

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("status code wants %d got %d", http.StatusSeeOther, resp.StatusCode)
	}

	l := resp.Header.Get("Location")
	// If IC calls reject to hydra, we can stop at this step and redirect to hydra.
	if l != hydraURL {
		t.Errorf("Location wants %s got %s", hydraURL, l)
	}
}

func TestAcceptLogin_Hydra_InvalidState(t *testing.T) {
	s, cfg, _, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	const (
		authCode = "non-admin," + idpName
	)

	resp, err := sendAcceptLogin(s, cfg, h, authCode, "invalid", "", "")
	if err != nil {
		t.Fatalf("sendAcceptLogin(s, cfg, h, %s, invalid, '', '') failed: %v", authCode, err)
	}

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status code wants %d got %d", http.StatusInternalServerError, resp.StatusCode)
	}
}

func sendFinishLogin(s *Service, cfg *pb.IcConfig, h *fakehydra.Server, idp, code, state string, step cpb.LoginState_Step) (*http.Response, error) {
	// Ensure login state exists before request.
	login := &cpb.LoginState{
		Provider:       idpName,
		Realm:          storage.DefaultRealm,
		LoginChallenge: loginChallenge,
		Step:           step,
	}

	if step == cpb.LoginState_CONSENT {
		login.ConsentChallenge = consentChallenge
	}

	err := s.store.Write(storage.LoginStateDatatype, storage.DefaultRealm, storage.DefaultUser, loginStateID, storage.LatestRev, login, nil)
	if err != nil {
		return nil, err
	}

	// Clear fakehydra server and set reject response.
	h.Clear()
	h.AcceptLoginResp = &hydraapi.RequestHandlerResponse{RedirectTo: hydraURL}
	h.RejectLoginResp = &hydraapi.RequestHandlerResponse{RedirectTo: hydraURL}

	// Send Request.
	path := strings.ReplaceAll(finishLoginPath, "{name}", idp)
	query := fmt.Sprintf("?code=%s&state=%s", code, state)
	u := "https://" + domain + path + query
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, u, nil)
	s.Handler.ServeHTTP(w, r)

	return w.Result(), nil
}

func TestFinishLogin_Hydra_Success(t *testing.T) {
	s, cfg, _, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	const (
		persona  = "non-admin"
		authCode = persona + ",cid"
	)

	resp, err := sendFinishLogin(s, cfg, h, idpName, authCode, loginStateID, cpb.LoginState_LOGIN)
	if err != nil {
		t.Fatalf("sendFinishLogin(s, cfg, h, %s, %s, %s, login) failed: %v", idpName, authCode, loginStateID, err)
	}

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("resp.StatusCode wants %d got %d", http.StatusSeeOther, resp.StatusCode)
	}

	l := resp.Header.Get("Location")
	if l != hydraURL {
		t.Errorf("Location wants %s got %s", hydraURL, l)
	}

	st, ok := h.AcceptLoginReq.Context[hydra.StateIDKey]
	if !ok {
		t.Errorf("AcceptLoginReq.Context[%s] not exists", hydra.StateIDKey)
	}
	stateID, ok := st.(string)
	if !ok {
		t.Errorf("AcceptLoginReq.Context[%s] is wrong type", hydra.StateIDKey)
	}

	state := &cpb.LoginState{}
	err = s.store.Read(storage.LoginStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, state)
	if err != nil {
		t.Fatalf("read LoginState failed: %v", err)
	}

	if state.Provider != idpName {
		t.Errorf("state.Provider wants %s got %s", idpName, state.Provider)
	}
	loginHint := idpName + ":" + persona
	if state.LoginHint != loginHint {
		t.Errorf("state.LoginHint wants %s got %s", loginHint, state.LoginHint)
	}
	if state.Step != cpb.LoginState_CONSENT {
		t.Errorf("state.Step wants %v got %v", cpb.LoginState_CONSENT, state.Step)
	}
	if *h.AcceptLoginReq.Subject != state.Subject {
		t.Errorf("subject send to hydra and subject in state should be equals. got %s, %s", *h.AcceptLoginReq.Subject, state.Subject)
	}
}

func TestFinishLogin_Hydra_Error(t *testing.T) {
	s, cfg, _, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	const (
		persona  = "non-admin"
		authCode = persona + ",cid"
	)

	tests := []struct {
		name   string
		idp    string
		state  string
		status int
	}{
		{
			name:   "invalid idp",
			idp:    "invalid",
			state:  loginStateID,
			status: http.StatusUnauthorized,
		},
		{
			name:   "invalid state",
			idp:    idpName,
			state:  "invalid",
			status: http.StatusInternalServerError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := sendFinishLogin(s, cfg, h, tc.idp, authCode, tc.state, cpb.LoginState_LOGIN)
			if err != nil {
				t.Fatalf("sendFinishLogin(s, cfg, h, %s, %s, %s, login) failed: %v", tc.idp, authCode, tc.state, err)
			}

			if resp.StatusCode != tc.status {
				t.Errorf("resp.StatusCode wants %d got %d", tc.status, resp.StatusCode)
			}

			if h.AcceptLoginReq != nil {
				t.Errorf("AcceptLoginReq wants nil got %v", h.AcceptLoginReq)
			}
		})
	}
}

func TestFinishLogin_Hydra_Error_AuthCode(t *testing.T) {
	s, cfg, _, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	h.RejectLoginResp = &hydraapi.RequestHandlerResponse{RedirectTo: hydraURL}

	resp, err := sendFinishLogin(s, cfg, h, idpName, "invalid", loginStateID, cpb.LoginState_LOGIN)
	if err != nil {
		t.Fatalf("sendFinishLogin(s, cfg, h, %s, %s, %s, login) failed: %v", idpName, "invalid", loginStateID, err)
	}

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("resp.StatusCode = %d, wants %d", resp.StatusCode, http.StatusSeeOther)
	}

	if h.RejectLoginReq.Code != http.StatusUnauthorized {
		t.Errorf("RejectLoginReq.Code = %d, wants %d", h.RejectLoginReq.Code, http.StatusUnauthorized)
	}
}

func TestFinishLogin_Hydra_Error_Step(t *testing.T) {
	s, cfg, _, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	h.RejectConsentResp = &hydraapi.RequestHandlerResponse{RedirectTo: hydraURL}

	resp, err := sendFinishLogin(s, cfg, h, idpName, "invalid", loginStateID, cpb.LoginState_CONSENT)
	if err != nil {
		t.Fatalf("sendFinishLogin(s, cfg, h, %s, %s, %s, consent) failed: %v", idpName, "invalid", loginStateID, err)
	}

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("resp.StatusCode = %d, wants %d", resp.StatusCode, http.StatusSeeOther)
	}

	if h.RejectConsentReq.Code != http.StatusUnauthorized {
		t.Errorf("RejectConsentReq.Code = %d, wants %d", h.RejectLoginReq.Code, http.StatusUnauthorized)
	}
}

func sendHydraConsent(t *testing.T, s *Service, h *fakehydra.Server, reqStateID string) *http.Response {
	t.Helper()

	h.GetConsentRequestResp = &hydraapi.ConsentRequest{
		RequestedScope:    []string{"openid", "profile"},
		Client:            &hydraapi.Client{Name: "test-client", ClientID: testClientID},
		Subject:           "admin",
		Context:           map[string]interface{}{hydra.StateIDKey: reqStateID},
		RequestedAudience: []string{"another_aud"},
	}

	state := &cpb.LoginState{Realm: "test", Subject: "admin"}
	err := s.store.Write(storage.LoginStateDatatype, storage.DefaultRealm, storage.DefaultUser, loginStateID, storage.LatestRev, state, nil)
	if err != nil {
		t.Fatalf("write LoginState failed: %v", err)
	}

	// Ensure identity exists before request.
	acct := &cpb.Account{
		Properties: &cpb.AccountProperties{Subject: "admin"},
		State:      "ACTIVE",
		ConnectedAccounts: []*cpb.ConnectedAccount{
			{
				Properties: &cpb.AccountProperties{
					Subject: "foo@bar.com",
				},
			},
		},
	}
	err = s.store.Write(storage.AccountDatatype, "test", storage.DefaultUser, "admin", storage.LatestRev, acct, nil)
	if err != nil {
		t.Fatalf("write Account failed: %v", err)
	}

	w := httptest.NewRecorder()
	params := fmt.Sprintf("?consent_challenge=%s", consentChallenge)
	u := "https://ic.example.com" + hydraConsentPath + params
	r := httptest.NewRequest(http.MethodGet, u, nil)

	s.Handler.ServeHTTP(w, r)

	return w.Result()
}

func TestConsent_Hydra(t *testing.T) {
	s, _, _, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	resp := sendHydraConsent(t, s, h, loginStateID)

	// return consent page
	if resp.StatusCode != http.StatusOK {
		t.Errorf("resp.StatusCode wants %d, got %d", http.StatusOK, resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "text/html" {
		t.Errorf("contentType = %s want text/html", contentType)
	}

	state := &cpb.LoginState{}
	err = s.store.Read(storage.LoginStateDatatype, storage.DefaultRealm, storage.DefaultUser, loginStateID, storage.LatestRev, state)
	if err != nil {
		t.Fatalf("read LoginState failed: %v", err)
	}

	if state.ConsentChallenge != consentChallenge {
		t.Errorf("state.ConsentChallenge = %s want %s", state.ConsentChallenge, consentChallenge)
	}

	wantScope := "openid profile"
	if state.Scope != wantScope {
		t.Errorf("state.Scope = %q want %q", state.Scope, wantScope)
	}

	wantAud := []string{"another_aud", testClientID}
	if diff := cmp.Diff(wantAud, state.Audience); len(diff) > 0 {
		t.Errorf("state.Audience (-want +got) %s", diff)
	}

	if state.ClientName != "test-client" {
		t.Errorf("state.ClientName = %s wants test-client", state.ClientName)
	}
}

func TestConsent_Hydra_StateInvalid(t *testing.T) {
	s, _, _, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	h.RejectConsentResp = &hydraapi.RequestHandlerResponse{RedirectTo: hydraURL}

	resp := sendHydraConsent(t, s, h, "invalid")

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("resp.StatusCode = %d, wants %d,", resp.StatusCode, http.StatusSeeOther)
	}

	if h.RejectConsentReq.Code != http.StatusInternalServerError {
		t.Errorf("RejectConsentReq.Code = %d, wants %d,", h.RejectConsentReq.Code, http.StatusInternalServerError)
	}
}

func TestConsent_Hydra_skipInformationRelease(t *testing.T) {
	s, _, _, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}
	s.skipInformationReleasePage = true

	h.AcceptConsentResp = &hydraapi.RequestHandlerResponse{RedirectTo: hydraURL}

	resp := sendHydraConsent(t, s, h, loginStateID)

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("resp.StatusCode wants %d, got %d", http.StatusSeeOther, resp.StatusCode)
	}

	if l := resp.Header.Get("Location"); l != hydraURL {
		t.Errorf("resp.Location wants %s got %s", hydraURL, l)
	}

	if h.RejectConsentReq != nil {
		t.Errorf("RejectConsentReq wants nil got %v", h.RejectConsentReq)
	}

	scope := "openid profile"
	if diff := cmp.Diff(h.AcceptConsentReq.GrantedScope, strings.Split(scope, " ")); len(diff) != 0 {
		t.Errorf("AcceptConsentReq.GrantedScope wants %s got %v", scope, h.AcceptConsentReq.GrantedScope)
	}

	email, ok := h.AcceptConsentReq.Session.IDToken["email"].(string)
	if !ok {
		t.Fatalf("Email in id token in wrong type")
	}

	wantEmail := "admin@" + domain
	if email != wantEmail {
		t.Errorf("Email in id token wants %s got %s", wantEmail, email)
	}
}

func TestConsent_Hydra_RememberedConsentOrInformationRelease(t *testing.T) {
	client := "test-client"
	expired := &cspb.RememberedConsentPreference{
		ClientName: client,
		ExpireTime: timeutil.TimestampProto(time.Time{}),
	}
	anything := &cspb.RememberedConsentPreference{
		ClientName:       client,
		ExpireTime:       timeutil.TimestampProto(time.Now().Add(time.Hour)),
		RequestMatchType: cspb.RememberedConsentPreference_ANYTHING,
	}
	scopeSame := &cspb.RememberedConsentPreference{
		ClientName:       client,
		ExpireTime:       timeutil.TimestampProto(time.Now().Add(time.Hour)),
		RequestMatchType: cspb.RememberedConsentPreference_SUBSET,
		RequestedScopes:  []string{"openid", "profile"},
	}
	scopeSubset := &cspb.RememberedConsentPreference{
		ClientName:       client,
		ExpireTime:       timeutil.TimestampProto(time.Now().Add(time.Hour)),
		RequestMatchType: cspb.RememberedConsentPreference_SUBSET,
		RequestedScopes:  []string{"openid"},
	}
	scopeNotMatch := &cspb.RememberedConsentPreference{
		ClientName:       client,
		ExpireTime:       timeutil.TimestampProto(time.Now().Add(time.Hour)),
		RequestMatchType: cspb.RememberedConsentPreference_SUBSET,
		RequestedScopes:  []string{"a1"},
	}

	tests := []struct {
		name          string
		remembered    map[string]*cspb.RememberedConsentPreference
		status        int
		consentAccept bool
	}{
		{
			name:   "no RememberedConsent",
			status: http.StatusOK,
		},
		{
			name: "expired RememberedConsent",
			remembered: map[string]*cspb.RememberedConsentPreference{
				"expired": expired,
			},
			status: http.StatusOK,
		},
		{
			name: "not match",
			remembered: map[string]*cspb.RememberedConsentPreference{
				"notmatch": scopeNotMatch,
			},
			status: http.StatusOK,
		},
		{
			name: "select anything",
			remembered: map[string]*cspb.RememberedConsentPreference{
				"expired":  expired,
				"anything": anything,
				"notmatch": scopeNotMatch,
				"subset":   scopeSubset,
			},
			status:        http.StatusSeeOther,
			consentAccept: true,
		},
		{
			name: "select anything",
			remembered: map[string]*cspb.RememberedConsentPreference{
				"expired":  expired,
				"anything": anything,
				"same":     scopeSame,
				"notmatch": scopeNotMatch,
				"subset":   scopeSubset,
			},
			status:        http.StatusSeeOther,
			consentAccept: true,
		},
		{
			name: "scope same",
			remembered: map[string]*cspb.RememberedConsentPreference{
				"expired":  expired,
				"same":     scopeSame,
				"notmatch": scopeNotMatch,
				"subset":   scopeSubset,
			},
			status:        http.StatusSeeOther,
			consentAccept: true,
		},
		{
			name: "scope subset",
			remembered: map[string]*cspb.RememberedConsentPreference{
				"expired":  expired,
				"notmatch": scopeNotMatch,
				"subset":   scopeSubset,
			},
			status:        http.StatusSeeOther,
			consentAccept: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _, h, _, err := setupHydraTest()
			if err != nil {
				t.Fatalf("setupHydraTest() failed: %v", err)
			}

			for k, v := range tc.remembered {
				err := s.store.Write(storage.RememberedConsentDatatype, "test", "admin", k, storage.LatestRev, v, nil)
				if err != nil {
					t.Fatalf("Write RememberedConsentDatatype failed: %v", err)
				}
			}

			h.AcceptConsentResp = &hydraapi.RequestHandlerResponse{RedirectTo: hydraURL}

			resp := sendHydraConsent(t, s, h, loginStateID)

			if resp.StatusCode != tc.status {
				t.Errorf("resp.StatusCode wants %d, got %d", tc.status, resp.StatusCode)
			}

			if tc.consentAccept {
				if h.AcceptConsentReq == nil {
					t.Errorf("should call AcceptConsentReq")
				}
			} else {
				if h.AcceptConsentReq != nil {
					t.Errorf("should not call AcceptConsentReq")
				}
			}
		})
	}
}

func icSendTestQuery(t *testing.T, method, path, pathname, realm, personaName string, query url.Values, data proto.Message, s *Service, iss *persona.Server) *http.Response {
	t.Helper()

	var p *cpb.TestPersona
	if iss.Config() != nil {
		p = iss.Config().TestPersonas[personaName]
	}

	clientID := ""
	cid := query["client_id"]
	if len(cid) > 0 {
		clientID = cid[0]
	}
	hydraPublicURL := hydraURL
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
	h := http.Header{"Authorization": []string{"Bearer " + string(tok)}}
	return testhttp.SendTestRequest(t, s.Handler, method, path, query, &buf, h)
}

func icSendTestRequest(t *testing.T, method, path, pathname, realm, personaName, clientID, clientSecret string, data proto.Message, s *Service, iss *persona.Server) *http.Response {
	t.Helper()

	q := url.Values{
		"client_id":     []string{clientID},
		"client_secret": []string{clientSecret},
	}
	return icSendTestQuery(t, method, path, pathname, realm, personaName, q, data, s, iss)
}

func TestClients_Get(t *testing.T) {
	s, cfg, sec, _, iss, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientName := "test_client"
	pname := "non-admin"
	cli := cfg.Clients[clientName]

	resp := icSendTestRequest(t, http.MethodGet, clientPath, clientName, "master", pname, cli.ClientId, sec.ClientSecrets[cli.ClientId], nil, s, iss)

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
	s, _, sec, _, iss, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	tests := []struct {
		name       string
		realm      string
		clientID   string
		clientName string
		status     int
	}{
		{
			name:       "client not exists",
			realm:      "master",
			clientID:   testClientID,
			clientName: "invalid",
			status:     http.StatusNotFound,
		},
		{
			name:       "client id and client name not match",
			realm:      "master",
			clientID:   testClientID,
			clientName: "test_client2",
			status:     http.StatusNotFound,
		},
		{
			name:       "not master realm",
			realm:      "test",
			clientID:   testClientID,
			clientName: "test_client",
			status:     http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pname := "non-admin"

			resp := icSendTestRequest(t, http.MethodGet, clientPath, tc.clientName, tc.realm, pname, tc.clientID, sec.ClientSecrets[tc.clientID], nil, s, iss)

			if resp.StatusCode != tc.status {
				t.Errorf("resp.StatusCode = %d, wants %d", resp.StatusCode, tc.status)
			}
		})
	}
}

func TestSyncClients_Get(t *testing.T) {
	s, cfg, sec, _, iss, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientName := "test_client"
	cli := cfg.Clients[clientName]

	resp := icSendTestRequest(t, http.MethodGet, syncClientsPath, clientName, "master", "", cli.ClientId, sec.ClientSecrets[cli.ClientId], nil, s, iss)

	wantStatus := http.StatusOK
	if resp.StatusCode != wantStatus {
		body, _ := ioutil.ReadAll(resp.Body)
		t.Fatalf("syncClients resp.StatusCode = %d, want %d, body = %s", resp.StatusCode, wantStatus, body)
	}
	got := &cpb.ClientState{}
	if err := jsonpb.Unmarshal(resp.Body, got); err != nil && err != io.EOF {
		t.Fatalf("jsonpb.Unmarshal() failed: %v", err)
	}
	if codes.Code(got.Status.Code) != codes.OK {
		t.Errorf("syncClients status code mismatch: got %d, want %d", got.Status.Code, codes.OK)
	}
}

func TestSyncClients_Post(t *testing.T) {
	s, cfg, sec, _, iss, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientName := "test_client"
	cli := cfg.Clients[clientName]

	resp := icSendTestRequest(t, http.MethodPost, syncClientsPath, clientName, "master", "", cli.ClientId, sec.ClientSecrets[cli.ClientId], nil, s, iss)

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
	s, cfg, sec, _, iss, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientName := "test_client2"
	cli := cfg.Clients[clientName]

	resp := icSendTestRequest(t, http.MethodGet, syncClientsPath, clientName, "master", "", cli.ClientId, sec.ClientSecrets[cli.ClientId], nil, s, iss)

	wantStatus := http.StatusForbidden
	if resp.StatusCode != wantStatus {
		t.Fatalf("clientsSync resp.StatusCode = %d, want %d", resp.StatusCode, wantStatus)
	}
}

func sendConfigClientsGet(t *testing.T, pname, clientName, realm, clientID, clientSecret string, s *Service, iss *persona.Server) *http.Response {
	t.Helper()

	var p *cpb.TestPersona
	if iss.Config() != nil {
		p = iss.Config().TestPersonas[pname]
	}

	tok, _, err := persona.NewAccessToken(pname, hydraURL, clientID, noScope, p)
	if err != nil {
		t.Fatalf("persona.NewAccessToken(%q, %q, _, _) failed: %v", pname, hydraURL, err)
	}

	path := strings.ReplaceAll(configClientsPath, "{realm}", realm)
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
	s, _, sec, _, iss, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	tests := []struct {
		name       string
		persona    string
		realm      string
		clientID   string
		clientName string
		status     int
	}{
		{
			name:       "client not exists",
			persona:    "admin",
			realm:      "master",
			clientID:   testClientID,
			clientName: "invalid",
			status:     http.StatusNotFound,
		},
		{
			name:       "not admin",
			persona:    "non-admin",
			realm:      "master",
			clientID:   testClientID,
			clientName: "test_client",
			status:     http.StatusUnauthorized,
		},
		{
			name:       "not master realm",
			persona:    "admin",
			realm:      "test",
			clientID:   testClientID,
			clientName: "test_client",
			status:     http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := sendConfigClientsGet(t, tc.persona, tc.clientName, tc.realm, tc.clientID, sec.ClientSecrets[tc.clientID], s, iss)

			if resp.StatusCode != tc.status {
				t.Errorf("resp.StatusCode = %d, wants %d", resp.StatusCode, tc.status)
			}
		})
	}
}

func diffOfHydraClientIgnoreClientIDAndSecret(c1 *hydraapi.Client, c2 *hydraapi.Client) string {
	return cmp.Diff(c1, c2, cmpopts.IgnoreFields(hydraapi.Client{}, "ClientID", "Secret", "CreatedAt"), cmpopts.IgnoreUnexported(strfmt.DateTime{}))
}

func sendConfigClientsCreate(t *testing.T, pname, clientName, realm, clientID, clientSecret string, cli *cpb.Client, s *Service, iss *persona.Server) *http.Response {
	t.Helper()

	var p *cpb.TestPersona
	if iss.Config() != nil {
		p = iss.Config().TestPersonas[pname]
	}

	tok, _, err := persona.NewAccessToken(pname, hydraURL, clientID, noScope, p)
	if err != nil {
		t.Fatalf("persona.NewAccessToken(%q, %q, _, _) failed: %v", pname, hydraURL, err)
	}

	m := jsonpb.Marshaler{}
	var buf bytes.Buffer
	if err := m.Marshal(&buf, &cpb.ConfigClientRequest{Item: cli}); err != nil {
		t.Fatal(err)
	}

	path := strings.ReplaceAll(configClientsPath, "{realm}", realm)
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

	resp := sendConfigClientsCreate(t, pname, clientName, "master", testClientID, testClientSecret, cli, s, iss)
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

	resp := sendConfigClientsCreate(t, pname, clientName, "master", testClientID, testClientSecret, cli, s, iss)
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

			resp := sendConfigClientsCreate(t, tc.persona, tc.clientName, tc.realm, testClientID, testClientSecret, tc.client, s, iss)

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

	resp := sendConfigClientsCreate(t, "admin", clientName, "master", testClientID, testClientSecret, cli, s, iss)

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

	return icSendTestRequest(t, http.MethodPatch, configClientsPath, clientName, realm, pname, clientID, clientSecret, &cpb.ConfigClientRequest{Item: cli}, s, iss)
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
		ClientID:      testClientID,
		Name:          clientName,
		Secret:        "secret",
		RedirectURIs:  cli.RedirectUris,
		Scope:         defaultScope,
		GrantTypes:    defaultGrantTypes,
		ResponseTypes: defaultResponseTypes,
	}

	query := url.Values{
		"client_id":     []string{test.TestClientID},
		"client_secret": []string{test.TestClientSecret},
		"rotate_secret": []string{"true"},
	}
	resp := icSendTestQuery(t, http.MethodPatch, configClientsPath, clientName, "master", pname, query, &cpb.ConfigClientRequest{Item: cli}, s, iss)
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

func TestConfigClients_Update_NoSecret(t *testing.T) {
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
		ClientID:      testClientID,
		Name:          clientName,
		RedirectURIs:  cli.RedirectUris,
		Scope:         defaultScope,
		GrantTypes:    defaultGrantTypes,
		ResponseTypes: defaultResponseTypes,
	}

	resp := sendConfigClientsUpdate(t, pname, clientName, "master", testClientID, testClientSecret, cli, s, iss)
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

	if got.ClientSecret != "" {
		t.Errorf("client secret should updated")
	}

	if len(h.UpdateClientReq.ClientID) == 0 {
		t.Errorf("should pass client id in hydra request")
	}

	if len(h.UpdateClientReq.Secret) != 0 {
		t.Errorf("should not pass secret in hydra request")
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
		ClientID:      testClientID,
		Name:          clientName,
		Secret:        "secret",
		RedirectURIs:  cli.RedirectUris,
		Scope:         defaultScope,
		GrantTypes:    defaultGrantTypes,
		ResponseTypes: defaultResponseTypes,
	}

	resp := sendConfigClientsUpdate(t, pname, clientName, "master", testClientID, testClientSecret, cli, s, iss)
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
				ClientID:      testClientID,
				Name:          clientName,
				Secret:        "secret",
				RedirectURIs:  cli.RedirectUris,
				Scope:         defaultScope,
				GrantTypes:    defaultGrantTypes,
				ResponseTypes: defaultResponseTypes,
			}

			resp := sendConfigClientsUpdate(t, tc.persona, tc.clientName, tc.realm, testClientID, testClientSecret, cli, s, iss)

			if resp.StatusCode != tc.status {
				t.Errorf("resp.StatusCode = %d, wants %d", resp.StatusCode, tc.status)
			}

			if h.UpdateClientReq != nil {
				t.Errorf("should not call Update client to hydra")
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
		ClientID:      testClientID,
		Name:          clientName,
		Secret:        "secret",
		RedirectURIs:  cli.RedirectUris,
		Scope:         defaultScope,
		GrantTypes:    defaultGrantTypes,
		ResponseTypes: defaultResponseTypes,
	}
	h.UpdateClientErr = &hydraapi.GenericError{Code: http.StatusServiceUnavailable}

	resp := sendConfigClientsUpdate(t, "admin", clientName, "master", testClientID, testClientSecret, cli, s, iss)

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

	tok, _, err := persona.NewAccessToken(pname, hydraURL, clientID, noScope, p)
	if err != nil {
		t.Fatalf("persona.NewAccessToken(%q, %q, _, _) failed: %v", pname, hydraURL, err)
	}

	path := strings.ReplaceAll(configClientsPath, "{realm}", realm)
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

	resp := sendConfigClientsDelete(t, pname, clientName, "master", testClientID, testClientSecret, s, iss)

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
	if _, ok := sec.ClientSecrets[testClientID]; ok {
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

			resp := sendConfigClientsDelete(t, tc.persona, tc.clientName, tc.realm, testClientID, testClientSecret, s, iss)

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
	s, cfg, _, h, iss, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientName := "test_client"

	h.DeleteClientErr = &hydraapi.GenericError{Code: http.StatusServiceUnavailable}

	resp := sendConfigClientsDelete(t, "admin", clientName, "master", testClientID, testClientSecret, s, iss)

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
	s, _, _, h, iss, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	cfg, err := s.loadConfig(nil, "master")
	if err != nil {
		t.Fatalf(`s.loadConfig(_, "master") failed: %v`, err)
	}
	sec, err := s.loadSecrets(nil)
	if err != nil {
		t.Fatalf(`s.loadSecrets(_) failed: %v`, err)
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
			Scope:         c.Scope,
			GrantTypes:    c.GrantTypes,
			ResponseTypes: c.ResponseTypes,
		})
	}
	h.ListClientsResp = existing
	h.UpdateClientResp = &hydraapi.Client{
		Name:          clientName,
		ClientID:      cli.ClientId,
		Secret:        sec.ClientSecrets[cli.ClientId],
		RedirectURIs:  cli.RedirectUris,
		Scope:         cli.Scope,
		GrantTypes:    cli.GrantTypes,
		ResponseTypes: cli.ResponseTypes,
	}

	pname := "admin"
	updatedScope := cli.Scope + " new-scope"
	cli.Scope = updatedScope

	// call update config
	resp := icSendTestRequest(t, http.MethodPut, configPath, "", "master", pname, test.TestClientID, test.TestClientSecret, &pb.ConfigRequest{Item: cfg}, s, iss)
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
	s, _, _, h, iss, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	cfg, err := s.loadConfig(nil, "test")
	if err != nil {
		t.Fatalf(`s.loadConfig(_, "test") failed: %v`, err)
	}
	sec, err := s.loadSecrets(nil)
	if err != nil {
		t.Fatalf(`s.loadSecrets(_) failed: %v`, err)
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
			Scope:         c.Scope,
			GrantTypes:    c.GrantTypes,
			ResponseTypes: c.ResponseTypes,
		})
	}
	h.ListClientsResp = existing
	h.UpdateClientResp = &hydraapi.Client{
		Name:          clientName,
		ClientID:      cli.ClientId,
		Secret:        sec.ClientSecrets[cli.ClientId],
		RedirectURIs:  cli.RedirectUris,
		Scope:         cli.Scope,
		GrantTypes:    cli.GrantTypes,
		ResponseTypes: cli.ResponseTypes,
	}

	pname := "admin"
	updatedScope := cli.Scope + " new-scope"
	cli.Scope = updatedScope

	// call update config
	resp := icSendTestRequest(t, http.MethodPut, configPath, "", "test", pname, test.TestClientID, test.TestClientSecret, &pb.ConfigRequest{Item: cfg}, s, iss)
	if resp.StatusCode != http.StatusForbidden {
		body, _ := ioutil.ReadAll(resp.Body)
		t.Errorf("icSendTestRequest().StatusCode = %d, want %d\n body: %v", resp.StatusCode, http.StatusForbidden, string(body))
	}
}

func TestConfigReset_Hydra(t *testing.T) {
	s, _, _, h, iss, err := setupHydraTest()
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

	tok, _, err := persona.NewAccessToken(pname, hydraURL, testClientID, noScope, p)
	if err != nil {
		t.Fatalf("persona.NewAccessToken(%q, %q, _, _) failed: %v", pname, hydraURL, err)
	}

	q := url.Values{
		"client_id":     []string{testClientID},
		"client_secret": []string{testClientSecret},
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

func TestConfigIdentityProviders_ClientSecret(t *testing.T) {
	store := storage.NewMemoryStorage("ic-min", "testdata/config")
	server, err := persona.NewBroker(hydraURL, &testkeys.PersonaBrokerKey, "dam-min", "testdata/config", false)
	if err != nil {
		t.Fatalf(`NewBroker() failed %v`, err)
	}

	crypt := fakeencryption.New()
	s := NewService(&Options{
		HTTPClient:     httptestclient.New(server.Handler),
		Domain:         domain,
		ServiceName:    "ic-min",
		AccountDomain:  domain,
		Store:          store,
		Encryption:     crypt,
		UseHydra:       useHydra,
		HydraAdminURL:  hydraAdminURL,
		HydraPublicURL: hydraURL,
		HydraSyncFreq:  time.Nanosecond,
	})

	sec, err := s.loadSecrets(nil)
	if err != nil {
		t.Fatalf(`s.loadSecret() failed %v`, err)
	}
	if sec.IdProviderSecrets == nil {
		sec.IdProviderSecrets = map[string]string{}
	}

	tests := []struct {
		name       string
		method     string
		issuerName string
		req        *pb.ConfigIdentityProviderRequest
		wantSecret func() map[string]string
	}{
		{
			name:       "add IdProvider",
			method:     http.MethodPost,
			issuerName: "iss0",
			req: &pb.ConfigIdentityProviderRequest{
				Item: &cpb.IdentityProvider{
					Issuer:       "https://example.com",
					AuthorizeUrl: "https://example.com/auth",
					TokenUrl:     "https://example.com/token",
					Ui: map[string]string{
						"label":       "foo",
						"description": "bar",
					},
					ClientId: "id0",
				},
			},
			wantSecret: func() map[string]string {
				return nil
			},
		},
		{
			name:       "get IdProvider",
			method:     http.MethodGet,
			issuerName: "iss0",
			wantSecret: func() map[string]string {
				return nil
			},
		},
		{
			name:       "add IdProvider with sec",
			method:     http.MethodPost,
			issuerName: "iss1",
			req: &pb.ConfigIdentityProviderRequest{
				Item: &cpb.IdentityProvider{
					Issuer:       "https://example.com",
					AuthorizeUrl: "https://example.com/auth",
					TokenUrl:     "https://example.com/token",
					Ui: map[string]string{
						"label":       "foo",
						"description": "bar",
					},
					ClientId: "id1",
				},
				ClientSecret: "sec",
			},
			wantSecret: func() map[string]string {
				sec.IdProviderSecrets["id1"] = "sec"
				return sec.IdProviderSecrets
			},
		},
		{
			name:       "get IdProvider",
			method:     http.MethodGet,
			issuerName: "iss1",
			wantSecret: func() map[string]string {
				return sec.IdProviderSecrets
			},
		},
		{
			name:       "update IdProvider without sec to iss0",
			method:     http.MethodPut,
			issuerName: "iss0",
			req: &pb.ConfigIdentityProviderRequest{
				Item: &cpb.IdentityProvider{
					Issuer:       "https://example.com/1",
					AuthorizeUrl: "https://example.com/auth",
					TokenUrl:     "https://example.com/token",
					Ui: map[string]string{
						"label":       "foo",
						"description": "bar",
					},
					ClientId: "id0",
				},
			},
			wantSecret: func() map[string]string {
				return sec.IdProviderSecrets
			},
		},
		{
			name:       "update IdProvider without sec",
			method:     http.MethodPut,
			issuerName: "iss1",
			req: &pb.ConfigIdentityProviderRequest{
				Item: &cpb.IdentityProvider{
					Issuer:       "https://example.com/1",
					AuthorizeUrl: "https://example.com/auth",
					TokenUrl:     "https://example.com/token",
					Ui: map[string]string{
						"label":       "foo",
						"description": "bar",
					},
					ClientId: "id1",
				},
			},
			wantSecret: func() map[string]string {
				return sec.IdProviderSecrets
			},
		},
		{
			name:       "update IdProvider with sec",
			method:     http.MethodPut,
			issuerName: "iss1",
			req: &pb.ConfigIdentityProviderRequest{
				Item: &cpb.IdentityProvider{
					Issuer:       "https://example.com/1",
					AuthorizeUrl: "https://example.com/auth",
					TokenUrl:     "https://example.com/token",
					Ui: map[string]string{
						"label":       "foo",
						"description": "bar",
					},
					ClientId: "id1",
				},
				ClientSecret: "sec1",
			},
			wantSecret: func() map[string]string {
				sec.IdProviderSecrets["id1"] = "sec1"
				return sec.IdProviderSecrets
			},
		},
		{
			name:       "patch IdProvider without secret to iss0",
			method:     http.MethodPatch,
			issuerName: "iss0",
			req: &pb.ConfigIdentityProviderRequest{
				Item: &cpb.IdentityProvider{
					Issuer: "https://example.com/1",
					Ui: map[string]string{
						"label":       "foo",
						"description": "bar",
					},
					ClientId: "id0",
				},
			},
			wantSecret: func() map[string]string {
				return sec.IdProviderSecrets
			},
		},
		{
			name:       "patch IdProvider without secret",
			method:     http.MethodPatch,
			issuerName: "iss1",
			req: &pb.ConfigIdentityProviderRequest{
				Item: &cpb.IdentityProvider{
					Issuer: "https://example.com/1",
					Ui: map[string]string{
						"label":       "foo",
						"description": "bar",
					},
					ClientId: "id1",
				},
			},
			wantSecret: func() map[string]string {
				return sec.IdProviderSecrets
			},
		},
		{
			name:       "patch IdProvider with secret",
			method:     http.MethodPatch,
			issuerName: "iss1",
			req: &pb.ConfigIdentityProviderRequest{
				Item: &cpb.IdentityProvider{
					Issuer: "https://example.com/1",
					Ui: map[string]string{
						"label":       "foo",
						"description": "bar",
					},
					ClientId: "id1",
				},
				ClientSecret: "sec2",
			},
			wantSecret: func() map[string]string {
				sec.IdProviderSecrets["id1"] = "sec2"
				return sec.IdProviderSecrets
			},
		},
		{
			name:       "delete IdProvider",
			method:     http.MethodDelete,
			issuerName: "iss1",
			wantSecret: func() map[string]string {
				return nil
			},
		},
	}

	pname := "admin"
	p := server.Config().TestPersonas[pname]
	tok, _, err := persona.NewAccessToken(pname, hydraURL, test.TestClientID, persona.DefaultScope, p)
	if err != nil {
		t.Fatalf("persona.NewAccessToken() failed: %v", err)
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q := url.Values{
				"client_id":     []string{test.TestClientID},
				"client_secret": []string{test.TestClientSecret},
			}
			path := strings.ReplaceAll(configIdentityProvidersPath, "{realm}", "test")
			path = strings.ReplaceAll(path, "{name}", tc.issuerName)
			header := http.Header{"Authorization": []string{"Bearer " + string(tok)}}

			var resp *http.Response
			if tc.req != nil {
				var buf bytes.Buffer
				if err := (&jsonpb.Marshaler{}).Marshal(&buf, tc.req); err != nil {
					t.Fatal(fmt.Errorf("marshaling message %+v failed: %v", tc.req, err))
				}
				resp = testhttp.SendTestRequest(t, s.Handler, tc.method, path, q, &buf, header)
			} else {
				resp = testhttp.SendTestRequest(t, s.Handler, tc.method, path, q, nil, header)
			}

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, wants %d", resp.StatusCode, http.StatusOK)
			}

			newSec, err := s.loadSecrets(nil)
			if err != nil {
				t.Fatalf(`s.loadSecret() failed %v`, err)
			}

			gotIDProviderSecrets := newSec.IdProviderSecrets
			if d := cmp.Diff(tc.wantSecret(), gotIDProviderSecrets); len(d) > 0 {
				t.Errorf("IdProviderSecrets in storage (-want, +got): %s", d)
			}
		})
	}
}
