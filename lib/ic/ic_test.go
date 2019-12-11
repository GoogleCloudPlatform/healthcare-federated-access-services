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
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang/protobuf/jsonpb" /* copybara-comment */
	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"github.com/google/go-cmp/cmp/cmpopts" /* copybara-comment */
	"github.com/gorilla/mux" /* copybara-comment */
	"github.com/coreos/go-oidc" /* copybara-comment */
	"github.com/go-openapi/strfmt" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/apis/hydraapi" /* copybara-comment: hydraapi */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common" /* copybara-comment: common */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/hydra" /* copybara-comment: hydra */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/kms/fakeencryption" /* copybara-comment: fakeencryption */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/persona" /* copybara-comment: persona */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakehydra" /* copybara-comment: fakehydra */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakeoidcissuer" /* copybara-comment: fakeoidcissuer */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/httptestclient" /* copybara-comment: httptestclient */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test" /* copybara-comment: test */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/testhttp" /* copybara-comment: testhttp */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */

	glog "github.com/golang/glog" /* copybara-comment */
	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/ic/v1" /* copybara-comment: go_proto */
)

const (
	domain           = "example.com"
	hydraAdminURL    = "https://admin.hydra.example.com"
	hydraURL         = "https://hydra.example.com"
	oidcIssuer       = "https://" + domain + "/oidc"
	testClientID     = "00000000-0000-0000-0000-000000000000"
	testClientSecret = "00000000-0000-0000-0000-000000000001"
	notUseHydra      = false
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

func TestOidcEndpoints(t *testing.T) {
	store := storage.NewMemoryStorage("ic-min", "testdata/config")
	s := NewService(context.Background(), domain, domain, hydraAdminURL, store, fakeencryption.New(), notUseHydra)
	cfg, err := s.loadConfig(nil, storage.DefaultRealm)
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}

	identity := &ga4gh.Identity{
		Subject: "sub",
	}
	tok, err := s.createToken(identity, "openid", oidcIssuer, "azp", storage.DefaultRealm, noNonce, time.Now(), time.Hour*1, cfg, nil)
	if err != nil {
		t.Fatalf("creating token: %v", err)
	}

	// Inject the mock http client to oidc client.
	client := httptestclient.New(s.Handler)
	ctx := oidc.ClientContext(context.Background(), client)
	provider, err := oidc.NewProvider(ctx, oidcIssuer)
	if err != nil {
		t.Fatal(err)
	}
	verifier := provider.Verifier(&oidc.Config{
		// TODO we should set correct "aud".
		ClientID: oidcIssuer,
	})

	_, err = verifier.Verify(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
}

func TestHandlers(t *testing.T) {
	store := storage.NewMemoryStorage("ic-min", "testdata/config")
	server, err := fakeoidcissuer.New(oidcIssuer, &testkeys.PersonaBrokerKey, "dam-min", "testdata/config")
	if err != nil {
		t.Fatalf("fakeoidcissuer.New(%q, _, _) failed: %v", oidcIssuer, err)
	}
	ctx := server.ContextWithClient(context.Background())
	crypt := fakeencryption.New()
	s := NewService(ctx, domain, domain, hydraAdminURL, store, crypt, notUseHydra)
	cfg, err := s.loadConfig(nil, "test")
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}
	identity := &ga4gh.Identity{
		Issuer:  s.getIssuerString(),
		Subject: "someone-account",
	}
	refreshToken1 := createTestToken(t, s, identity, "openid refresh", cfg)
	refreshToken2 := createTestToken(t, s, identity, "openid refresh", cfg)
	tests := []test.HandlerTest{
		{
			Name:   "Get a self-owned token",
			Method: "GET",
			Path:   "/identity/v1alpha/test/token/dr_joe_elixir/123-456",
			Output: `{"tokenMetadata":{"tokenType":"refresh","issuedAt":"1560970669","scope":"ga4gh_passport_v1 identities profiles openid","identityProvider":"elixir"}}`,
			Status: http.StatusOK,
		},
		{
			Name:    "Get someone else's token as an admin",
			Method:  "GET",
			Path:    "/identity/v1alpha/test/token/someone-account/1a2-3b4",
			Persona: "admin",
			Output:  `{"tokenMetadata":{"tokenType":"refresh","issuedAt":"1560970669","scope":"ga4gh_passport_v1 openid","identityProvider":"google"}}`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get someone else's token as an non-admin",
			Method:  "GET",
			Path:    "/identity/v1alpha/test/token/dr_joe_elixir/1a2-3b4",
			Persona: "non-admin",
			Output:  `^.*token not found.*`,
			Status:  http.StatusNotFound,
		},
		{
			Name:   "Post a self-owned token",
			Method: "POST",
			Path:   "/identity/v1alpha/test/token/dr_joe_elixir/123-456",
			Output: `^.*exists`,
			Status: http.StatusConflict,
		},
		{
			Name:   "Put a self-owned token",
			Method: "PUT",
			Path:   "/identity/v1alpha/test/token/dr_joe_elixir/123-456",
			Output: `^.*not allowed`,
			Status: http.StatusBadRequest,
		},
		{
			Name:   "Patch a self-owned token",
			Method: "PATCH",
			Path:   "/identity/v1alpha/test/token/dr_joe_elixir/123-456",
			Output: `^.*not allowed`,
			Status: http.StatusBadRequest,
		},
		{
			Name:   "Delete a self-owned token",
			Method: "DELETE",
			Path:   "/identity/v1alpha/test/token/dr_joe_elixir/123-456",
			Output: "",
			Status: http.StatusOK,
		},
		{
			Name:   "Get a deleted token",
			Method: "GET",
			Path:   "/identity/v1alpha/test/token/dr_joe_elixir/123-456",
			Output: `^.*token not found.*`,
			Status: http.StatusNotFound,
		},
		{
			Name:   "Request an unsupported method at the /revoke endpoint",
			Method: "GET",
			Path:   "/identity/v1alpha/test/revoke",
			Input:  `token=6ImtpZCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJpY19lOWIxMDA2MDd`,
			IsForm: true,
			Output: `^.*method not supported.*`,
			Status: http.StatusBadRequest,
		},
		{
			Name:   "Delete a malformed token",
			Method: "POST",
			Path:   "/identity/v1alpha/test/revoke",
			Input:  `token=6ImtpZCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJpY19lOWIxMDA2MDd`,
			IsForm: true,
			Output: `^.*inspecting token.*`,
			Status: http.StatusUnauthorized,
		},
		{
			Name:    "Delete someone else's token as an admin",
			Method:  "POST",
			Path:    "/identity/v1alpha/test/revoke",
			Persona: "admin",
			Input:   "token=" + refreshToken1,
			IsForm:  true,
			Output:  "",
			Status:  http.StatusOK,
		},
		{
			Name:    "Delete someone else's token as a non-admin",
			Method:  "POST",
			Path:    "/identity/v1alpha/test/revoke",
			Input:   "token=" + refreshToken2,
			IsForm:  true,
			Persona: "non-admin",
			Output:  "",
			Status:  http.StatusOK,
		},
		{
			Name:    "Get linked accounts (foo)",
			Method:  "GET",
			Path:    "/identity/v1alpha/test/accounts/non-admin/subjects/foo",
			Persona: "admin",
			Output:  "^.*not found",
			Status:  http.StatusNotFound,
		},
		{
			Name:    "Get linked accounts (foo@bar.com)",
			Method:  "GET",
			Path:    "/identity/v1alpha/test/accounts/non-admin/subjects/foo@bar.com",
			Persona: "admin",
			Output:  "^.*not found",
			Status:  http.StatusNotFound,
		},
		{
			Name:    "Get account",
			Method:  "GET",
			Path:    "/identity/v1alpha/test/accounts/-",
			Persona: "non-admin",
			Output:  `^.*non-admin@example.org.*"passport"`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM users",
			Method:  "GET",
			Path:    "/identity/scim/v2/test/Users",
			Persona: "admin",
			Output:  `{"Resources":[{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"admin","externalId":"admin","meta":{"resourceType":"User","created":"2019-06-22T13:29:50Z","lastModified":"2019-06-22T18:07:30Z","location":"https://example.com/identity/scim/v2/test/Users/admin","version":"1"},"userName":"admin","name":{"formatted":"Administrator"},"active":true,"emails":[{}]},{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"dr_joe_elixir","externalId":"dr_joe_elixir","meta":{"resourceType":"User","created":"2019-06-22T13:29:40Z","lastModified":"2019-06-22T18:07:20Z","location":"https://example.com/identity/scim/v2/test/Users/dr_joe_elixir","version":"1"},"userName":"dr_joe_elixir","name":{"formatted":"Dr. Joe (ELIXIR)"},"active":true},{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"non-admin","externalId":"non-admin","meta":{"resourceType":"User","created":"2019-06-22T13:29:59Z","lastModified":"2019-06-22T18:08:19Z","location":"https://example.com/identity/scim/v2/test/Users/non-admin","version":"1"},"userName":"non-admin","name":{"formatted":"Non Administrator"},"active":true,"emails":[{"value":"non-admin@example.org"}]},{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"someone-account","externalId":"someone-account","meta":{"resourceType":"User","created":"2019-06-22T13:29:36Z","lastModified":"2019-06-22T18:07:11Z","location":"https://example.com/identity/scim/v2/test/Users/someone-account","version":"1"},"userName":"someone-account","name":{"formatted":"Someone Account"},"active":true}],"startIndex":1,"itemsPerPage":4,"totalResults":4,"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"]}`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM users (paginate)",
			Method:  "GET",
			Path:    "/identity/scim/v2/test/Users",
			Params:  "startIndex=3&count=1",
			Persona: "admin",
			Output:  `^.*"startIndex":3,"itemsPerPage":1,"totalResults":4,.*`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM users - filter id",
			Method:  "GET",
			Path:    "/identity/scim/v2/test/Users",
			Persona: "admin",
			Params:  `filter=id%20co%20"admin"`,
			Output:  `{"Resources":[{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"admin","externalId":"admin","meta":{"resourceType":"User","created":"2019-06-22T13:29:50Z","lastModified":"2019-06-22T18:07:30Z","location":"https://example.com/identity/scim/v2/test/Users/admin","version":"1"},"userName":"admin","name":{"formatted":"Administrator"},"active":true,"emails":[{}]},{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"non-admin","externalId":"non-admin","meta":{"resourceType":"User","created":"2019-06-22T13:29:59Z","lastModified":"2019-06-22T18:08:19Z","location":"https://example.com/identity/scim/v2/test/Users/non-admin","version":"1"},"userName":"non-admin","name":{"formatted":"Non Administrator"},"active":true,"emails":[{"value":"non-admin@example.org"}]}],"startIndex":1,"itemsPerPage":2,"totalResults":2,"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"]}`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM users - filter name.formatted",
			Method:  "GET",
			Path:    "/identity/scim/v2/test/Users",
			Persona: "admin",
			Params:  `filter=name.formatted%20co%20"administrator"`,
			Output:  `{"Resources":[{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"admin","externalId":"admin","meta":{"resourceType":"User","created":"2019-06-22T13:29:50Z","lastModified":"2019-06-22T18:07:30Z","location":"https://example.com/identity/scim/v2/test/Users/admin","version":"1"},"userName":"admin","name":{"formatted":"Administrator"},"active":true,"emails":[{}]},{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"non-admin","externalId":"non-admin","meta":{"resourceType":"User","created":"2019-06-22T13:29:59Z","lastModified":"2019-06-22T18:08:19Z","location":"https://example.com/identity/scim/v2/test/Users/non-admin","version":"1"},"userName":"non-admin","name":{"formatted":"Non Administrator"},"active":true,"emails":[{"value":"non-admin@example.org"}]}],"startIndex":1,"itemsPerPage":2,"totalResults":2,"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"]}`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM users - filter OR clause",
			Method:  "GET",
			Path:    "/identity/scim/v2/test/Users",
			Persona: "admin",
			Params:  `filter=name.formatted%20co%20"administrator"%20or%20userName%20co%20"joe"`,
			Output:  `{"Resources":[{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"admin","externalId":"admin","meta":{"resourceType":"User","created":"2019-06-22T13:29:50Z","lastModified":"2019-06-22T18:07:30Z","location":"https://example.com/identity/scim/v2/test/Users/admin","version":"1"},"userName":"admin","name":{"formatted":"Administrator"},"active":true,"emails":[{}]},{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"dr_joe_elixir","externalId":"dr_joe_elixir","meta":{"resourceType":"User","created":"2019-06-22T13:29:40Z","lastModified":"2019-06-22T18:07:20Z","location":"https://example.com/identity/scim/v2/test/Users/dr_joe_elixir","version":"1"},"userName":"dr_joe_elixir","name":{"formatted":"Dr. Joe (ELIXIR)"},"active":true},{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"non-admin","externalId":"non-admin","meta":{"resourceType":"User","created":"2019-06-22T13:29:59Z","lastModified":"2019-06-22T18:08:19Z","location":"https://example.com/identity/scim/v2/test/Users/non-admin","version":"1"},"userName":"non-admin","name":{"formatted":"Non Administrator"},"active":true,"emails":[{"value":"non-admin@example.org"}]}],"startIndex":1,"itemsPerPage":3,"totalResults":3,"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"]}`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM users (non-admin)",
			Method:  "GET",
			Path:    "/identity/scim/v2/test/Users",
			Persona: "non-admin",
			Scope:   persona.AccountScope,
			Output:  `^.*not an administrator.*`,
			Status:  http.StatusForbidden,
		},
		{
			Name:    "Get SCIM me",
			Method:  "GET",
			Path:    "/identity/scim/v2/test/Me",
			Persona: "non-admin",
			Scope:   persona.AccountScope,
			Output:  `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"non-admin","externalId":"non-admin","meta":{"resourceType":"User","created":"2019-06-22T13:29:59Z","lastModified":"2019-06-22T18:08:19Z","location":"https://example.com/identity/scim/v2/test/Users/non-admin","version":"1"},"userName":"non-admin","name":{"formatted":"Non Administrator"},"active":true,"emails":[{"value":"non-admin@example.org"}]}`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM me (default scope)",
			Method:  "GET",
			Path:    "/identity/scim/v2/test/Me",
			Persona: "non-admin",
			Output:  `^.*urn:ietf:params:scim:schemas:core:2.0:User.*`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Patch SCIM me (default scope)",
			Method:  "PATCH",
			Path:    "/identity/scim/v2/test/Me",
			Persona: "non-admin",
			Input:   `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"name.formatted","value":"Non-Administrator"},{"op":"replace","path":"active","value":"false"}]}`,
			Output:  `^.*unauthorized.*`,
			Status:  http.StatusUnauthorized,
		},
		{
			Name:    "Patch SCIM me (bad photo)",
			Method:  "PATCH",
			Path:    "/identity/scim/v2/test/Me",
			Persona: "non-admin",
			Scope:   persona.AccountScope,
			Input:   `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"photos[type eq \"thumbnail\"].value","value":"I am a teapot"}]}`,
			Output:  `^.*invalid photo.*`,
			Status:  http.StatusBadRequest,
		},
		{
			Name:    "Patch SCIM me (update photo)",
			Method:  "PATCH",
			Path:    "/identity/scim/v2/test/Me",
			Persona: "non-admin",
			Scope:   persona.AccountScope,
			Input:   `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"photos[type eq \"thumbnail\"].value","value":"https://my.example.org/photos/me.jpeg"}]}`,
			Output:  `^.*"photos":\[\{"primary":true,"value":"https://my.example.org/photos/me.jpeg"\}\]`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Patch SCIM me (multiple ops)",
			Method:  "PATCH",
			Path:    "/identity/scim/v2/test/Me",
			Persona: "non-admin",
			Scope:   persona.AccountScope,
			Input:   `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"name.formatted","value":"Non-Administrator"},{"op":"replace","path":"active","value":"false"}]}`,
			Output:  `^\{"schemas":\["urn:ietf:params:scim:schemas:core:2.0:User"\],"id":"non-admin","externalId":"non-admin","meta":\{"resourceType":"User","created":"2019-06-22T13:29:59Z","lastModified":"....-..-..T..:..:..Z","location":"https://example.com/identity/scim/v2/test/Users/non-admin","version":"2"\},"userName":"non-admin","name":\{"formatted":"Non-Administrator"\},"emails":\[\{"value":"non-admin@example.org"\}\],"photos":\[\{"primary":true,"value":"https://my.example.org/photos/me.jpeg"\}\]\}`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Patch SCIM active (admin)",
			Method:  "PATCH",
			Path:    "/identity/scim/v2/test/Users/non-admin",
			Persona: "admin",
			Input:   `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":"true"}]}`,
			Output:  `^\{"schemas":\["urn:ietf:params:scim:schemas:core:2.0:User"\],"id":"non-admin","externalId":"non-admin","meta":\{"resourceType":"User","created":"2019-06-22T13:29:59Z","lastModified":"20..-..-..T..:..:..Z","location":"https://example.com/identity/scim/v2/test/Users/non-admin","version":"3"},"userName":"non-admin","name":\{"formatted":"Non-Administrator"\},"active":true,"emails":\[\{"value":"non-admin@example.org"\}\],"photos":\[\{"primary":true,"value":"https://my.example.org/photos/me.jpeg"\}\]\}`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Delete SCIM me (default scope)",
			Method:  "DELETE",
			Path:    "/identity/scim/v2/test/Me",
			Persona: "non-admin",
			Output:  `^.*unauthorized.*`,
			Status:  http.StatusUnauthorized,
		},
		{
			Name:    "Delete SCIM me",
			Method:  "DELETE",
			Path:    "/identity/scim/v2/test/Me",
			Persona: "non-admin",
			Scope:   persona.AccountScope,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM me",
			Method:  "GET",
			Path:    "/identity/scim/v2/test/Me",
			Persona: "non-admin",
			Scope:   persona.AccountScope,
			Output:  `^.*unauthorized.*`,
			Status:  http.StatusUnauthorized,
		},
		{
			Name:    "Get SCIM account (admin)",
			Method:  "GET",
			Path:    "/identity/scim/v2/test/Users/dr_joe_elixir",
			Persona: "admin",
			Output:  `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"dr_joe_elixir","externalId":"dr_joe_elixir","meta":{"resourceType":"User","created":"2019-06-22T13:29:40Z","lastModified":"2019-06-22T18:07:20Z","location":"https://example.com/identity/scim/v2/test/Users/dr_joe_elixir","version":"1"},"userName":"dr_joe_elixir","name":{"formatted":"Dr. Joe (ELIXIR)"},"active":true}`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM account",
			Method:  "GET",
			Path:    "/identity/scim/v2/test/Users/dr_joe_elixir",
			Persona: "dr_joe_elixir",
			Scope:   persona.AccountScope,
			Output:  `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"dr_joe_elixir","externalId":"dr_joe_elixir","meta":{"resourceType":"User","created":"2019-06-22T13:29:40Z","lastModified":"2019-06-22T18:07:20Z","location":"https://example.com/identity/scim/v2/test/Users/dr_joe_elixir","version":"1"},"userName":"dr_joe_elixir","name":{"formatted":"Dr. Joe (ELIXIR)"},"active":true}`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get SCIM account (default scope)",
			Method:  "GET",
			Path:    "/identity/scim/v2/test/Users/dr_joe_elixir",
			Persona: "dr_joe_elixir",
			Output:  `^.*urn:ietf:params:scim:schemas:core:2.0:User.*`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Patch SCIM account",
			Method:  "PATCH",
			Path:    "/identity/scim/v2/test/Users/dr_joe_elixir",
			Persona: "dr_joe_elixir",
			Scope:   persona.AccountScope,
			Input:   `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"name.formatted","value":"The good doc"},{"op":"replace","path":"name.givenName","value":"Joesph"},{"op":"replace","path":"name.familyName","value":"Doctor"}]}`,
			Output:  `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"dr_joe_elixir","externalId":"dr_joe_elixir","meta":{"resourceType":"User","created":"2019-06-22T13:29:40Z","lastModified":"2019-06-22T18:07:20Z","location":"https://example.com/identity/scim/v2/test/Users/dr_joe_elixir","version":"1"},"userName":"dr_joe_elixir","name":{"formatted":"The good doc","familyName":"Doctor","givenName":"Joesph"},"active":true}`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Patch SCIM account (default scope)",
			Method:  "PATCH",
			Path:    "/identity/scim/v2/test/Users/dr_joe_elixir",
			Persona: "dr_joe_elixir",
			Input:   `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"name.formatted","value":"The good doc"},{"op":"replace","path":"name.givenName","value":"Joesph"},{"op":"replace","path":"name.familyName","value":"Doctor"}]}`,
			Output:  `^.*unauthorized.*`,
			Status:  http.StatusUnauthorized,
		},
		{
			Name:    "Delete SCIM account (default scope)",
			Method:  "DELETE",
			Path:    "/identity/scim/v2/test/Users/dr_joe_elixir",
			Persona: "dr_joe_elixir",
			Output:  `^.*unauthorized.*`,
			Status:  http.StatusUnauthorized,
		},
		{
			Name:    "Delete SCIM account",
			Method:  "DELETE",
			Path:    "/identity/scim/v2/test/Users/dr_joe_elixir",
			Persona: "dr_joe_elixir",
			Scope:   persona.AccountScope,
			Status:  http.StatusOK,
		},
		{
			Name:    "Get deleted SCIM account",
			Method:  "GET",
			Path:    "/identity/scim/v2/test/Users/dr_joe_elixir",
			Persona: "dr_joe_elixir",
			Scope:   persona.AccountScope,
			Output:  `^.*unauthorized.*`,
			Status:  http.StatusUnauthorized,
		},
		{
			Name:    "Get deleted SCIM account (admin)",
			Method:  "GET",
			Path:    "/identity/scim/v2/test/Users/dr_joe_elixir",
			Persona: "admin",
			Output:  `^.*dr_joe_elixir.*`,
			Status:  http.StatusOK,
		},
		{
			Name:    "Undelete SCIM account (admin)",
			Method:  "PATCH",
			Path:    "/identity/scim/v2/test/Users/dr_joe_elixir",
			Persona: "admin",
			Input:   `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":"true"}]}`,
			Output:  `^.*dr_joe_elixir.*"active":true.*`,
			Status:  http.StatusOK,
		},
	}
	test.HandlerTests(t, s.Handler, tests, oidcIssuer, server.Config())
}

func createTestToken(t *testing.T, s *Service, id *ga4gh.Identity, scope string, cfg *pb.IcConfig) string {
	token, err := s.createToken(id, scope, "", "", "test", noNonce, time.Now(), time.Hour, cfg, nil)
	if err != nil {
		t.Fatalf("creating test token: %v", err)
	}
	return token
}

func TestAdminHandlers(t *testing.T) {
	store := storage.NewMemoryStorage("ic-min", "testdata/config")
	server, err := fakeoidcissuer.New(oidcIssuer, &testkeys.PersonaBrokerKey, "dam-min", "testdata/config")
	if err != nil {
		t.Fatalf("fakeoidcissuer.New(%q, _, _) failed: %v", oidcIssuer, err)
	}
	ctx := server.ContextWithClient(context.Background())

	s := NewService(ctx, domain, domain, hydraAdminURL, store, fakeencryption.New(), notUseHydra)
	tests := []test.HandlerTest{
		{
			Name:    "List all tokens of all users as a non-admin",
			Method:  "GET",
			Path:    "/identity/v1alpha/test/admin/tokens",
			Persona: "non-admin",
			Output: `^.*user is not an administrator	*`,
			Status: http.StatusForbidden,
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
			Output: `^.*user is not an administrator	*`,
			Status: http.StatusForbidden,
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
	}
	test.HandlerTests(t, s.Handler, tests, oidcIssuer, server.Config())
}

func TestNonce(t *testing.T) {
	nonce := "nonce-for-test"
	store := storage.NewMemoryStorage("ic-min", "testdata/config")
	s := NewService(context.Background(), domain, domain, hydraAdminURL, store, fakeencryption.New(), notUseHydra)
	cfg, err := s.loadConfig(nil, "test")
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}

	// Auth Code should not include "nonce".
	auth, err := s.createAuthToken("someone-account", "openid", "persona", "test", nonce, time.Now(), cfg, nil)
	if err != nil {
		t.Fatalf("creating auth token: %v", err)
	}
	id, err := common.ConvertTokenToIdentityUnsafe(auth)
	if err != nil {
		t.Fatalf("ConvertTokenToIdentityUnsafe(%q) error: %v", auth, err)
	}
	if len(id.Nonce) > 0 {
		t.Error("Auth Code should not include 'nonce'")
	}

	path := strings.ReplaceAll(tokenPath, "{realm}", "test")

	// ID token request by auth code should include "nonce".
	w := httptest.NewRecorder()
	params := fmt.Sprintf("grant_type=authorization_code&client_id=%s&client_secret=%s&redirect_uri=http://example.com&code=%s", testClientID, testClientSecret, auth)
	r := httptest.NewRequest("POST", path+"?"+params, nil)
	s.Handler.ServeHTTP(w, r)
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("get tokens by auth code want ok, got %q", resp.Status)
	}

	unmarshaler := jsonpb.Unmarshaler{}
	tokens := cpb.OidcTokenResponse{}
	err = unmarshaler.Unmarshal(resp.Body, &tokens)
	if err != nil {
		t.Fatalf("unmarshal failed")
	}
	id, err = common.ConvertTokenToIdentityUnsafe(tokens.IdToken)
	if err != nil {
		t.Errorf("ConvertTokenToIdentityUnsafe(%q) error: %v", tokens.IdToken, err)
	}
	if id.Nonce != nonce {
		t.Errorf("get tokens by auth code, id_token.nonce incorrect: want %q, got %q", id.Nonce, nonce)
	}
	access, err := common.ConvertTokenToIdentityUnsafe(tokens.AccessToken)
	if err != nil {
		t.Errorf("ConvertTokenToIdentityUnsafe(%q) error: %v", tokens.AccessToken, err)
	}
	if len(access.Nonce) > 0 {
		t.Error("access token should not include nonce")
	}
	refresh, err := common.ConvertTokenToIdentityUnsafe(tokens.RefreshToken)
	if err != nil {
		t.Errorf("ConvertTokenToIdentityUnsafe(%q) error: %v", tokens.RefreshToken, err)
	}
	if len(refresh.Nonce) > 0 {
		t.Error("refresh token should not include nonce")
	}

	// ID token request by refresh token should not include "nonce".
	w = httptest.NewRecorder()
	params = fmt.Sprintf("grant_type=refresh_token&client_id=%s&client_secret=%s&redirect_uri=http://example.com&refresh_token=%s", testClientID, testClientSecret, tokens.RefreshToken)
	r = httptest.NewRequest("POST", path+"?"+params, nil)
	s.Handler.ServeHTTP(w, r)
	resp = w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("get tokens by refresh token want ok, got %q", resp.Status)
	}
	err = unmarshaler.Unmarshal(resp.Body, &tokens)
	if err != nil {
		t.Error("unmarshal failed")
	}
	id, err = common.ConvertTokenToIdentityUnsafe(tokens.IdToken)
	if len(id.Nonce) > 0 {
		t.Error("get tokens by refresh token, id token not include nonce")
	}
	access, err = common.ConvertTokenToIdentityUnsafe(tokens.AccessToken)
	if len(access.Nonce) > 0 {
		t.Error("access token should not include nonce")
	}
	refresh, err = common.ConvertTokenToIdentityUnsafe(tokens.RefreshToken)
	if len(refresh.Nonce) > 0 {
		t.Error("refresh token should not include nonce")
	}
}

func TestAddLinkedIdentities(t *testing.T) {
	subject := "111@a.com"
	issuer := "https://example.com/oidc"
	subjectInIdp := "222"
	emailInIdp := "222@idp.com"
	idp := "idp"
	idpIss := "https://idp.com/oidc"

	id := &ga4gh.Identity{
		Subject:  subject,
		Issuer:   issuer,
		VisaJWTs: []string{},
	}

	link := &pb.ConnectedAccount{
		Provider: idp,
		Properties: &pb.AccountProperties{
			Subject: subjectInIdp,
			Email:   emailInIdp,
		},
	}

	store := storage.NewMemoryStorage("ic-min", "testdata/config")
	s := NewService(context.Background(), domain, domain, hydraAdminURL, store, fakeencryption.New(), notUseHydra)
	cfg, err := s.loadConfig(nil, storage.DefaultRealm)
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}
	cfg.IdentityProviders = map[string]*pb.IdentityProvider{
		idp: &pb.IdentityProvider{Issuer: idpIss},
	}

	err = s.addLinkedIdentities(id, link, testkeys.Default.Private, cfg)
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
		Scope: "openid",
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
}

func setupHydraTest() (*Service, *pb.IcConfig, *fakehydra.Server, *fakeoidcissuer.Server, error) {
	store := storage.NewMemoryStorage("ic-min", "testdata/config")
	server, err := fakeoidcissuer.New(oidcIssuer, &testkeys.PersonaBrokerKey, "dam-min", "testdata/config")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	ctx := server.ContextWithClient(context.Background())
	crypt := fakeencryption.New()
	s := NewService(ctx, domain, domain, hydraAdminURL, store, crypt, useHydra)

	cfg, err := s.loadConfig(nil, storage.DefaultRealm)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	r := mux.NewRouter()
	h := fakehydra.New(r)
	s.httpClient = httptestclient.New(r)

	return s, cfg, h, server, nil
}

func TestLogin_Hydra(t *testing.T) {
	s, cfg, _, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	w := httptest.NewRecorder()
	params := fmt.Sprintf("?scope=openid&login_challenge=%s", loginChallenge)
	u := "https://ic.example.com" + loginPath + params
	u = strings.ReplaceAll(u, "{realm}", storage.DefaultRealm)
	u = strings.ReplaceAll(u, "{name}", idpName)
	r := httptest.NewRequest(http.MethodGet, u, nil)

	s.Handler.ServeHTTP(w, r)

	resp := w.Result()

	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("resp.StatusCode wants %d, got %d", http.StatusTemporaryRedirect, resp.StatusCode)
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

	if loginState.Challenge != loginChallenge {
		t.Errorf("state.Challenge wants %s got %s", loginChallenge, loginState.Challenge)
	}
	if loginState.IdpName != idpName {
		t.Errorf("state.IdpName wants %s got %s", idpName, loginState.IdpName)
	}
}

func sendAcceptLogin(s *Service, cfg *pb.IcConfig, h *fakehydra.Server, code, state, errName, errDesc string) (*http.Response, error) {
	idpc := cfg.IdentityProviders[idpName]

	// Ensure login state exists before request.
	login := &cpb.LoginState{
		IdpName:   idpName,
		Realm:     storage.DefaultRealm,
		Scope:     strings.Join(idpc.Scopes, " "),
		Challenge: loginChallenge,
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
	s, cfg, h, _, err := setupHydraTest()
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

			if resp.StatusCode != http.StatusTemporaryRedirect {
				t.Errorf("statusCode wants %d got %d", http.StatusTemporaryRedirect, resp.StatusCode)
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
	s, cfg, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	const (
		errName = "idpErr"
		errDesc = "Error message from upstream idp"
	)

	resp, err := sendAcceptLogin(s, cfg, h, "", loginStateID, errName, errDesc)
	if err != nil {
		t.Fatalf("sendAcceptLogin(s, cfg, h, '', %s, %s, %s) failed: %v", hydra.StateIDKey, errName, errDesc, err)
	}

	if h.RejectLoginReq.Name != errName {
		t.Errorf("RejectLoginReq.Name wants %s got %s", errName, h.RejectLoginReq.Name)
	}
	if h.RejectLoginReq.Description != errDesc {
		t.Errorf("RejectLoginReq.Description wants %s got %s", errDesc, h.RejectLoginReq.Description)
	}

	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("status code wants %d got %d", http.StatusTemporaryRedirect, resp.StatusCode)
	}

	l := resp.Header.Get("Location")
	// If IC calls reject to hydra, we can stop at this step and redirect to hydra.
	if l != hydraURL {
		t.Errorf("Location wants %s got %s", hydraURL, l)
	}
}

func TestAcceptLogin_Hydra_InvalidState(t *testing.T) {
	s, cfg, h, _, err := setupHydraTest()
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

func sendFinishLogin(s *Service, cfg *pb.IcConfig, h *fakehydra.Server, idp, code, state string) (*http.Response, error) {
	idpc := cfg.IdentityProviders[idpName]

	// Ensure login state exists before request.
	login := &cpb.LoginState{
		IdpName:   idpName,
		Realm:     storage.DefaultRealm,
		Scope:     strings.Join(idpc.Scopes, " "),
		Challenge: loginChallenge,
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
	s, cfg, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	const (
		persona  = "non-admin"
		authCode = persona + ",cid"
	)

	resp, err := sendFinishLogin(s, cfg, h, idpName, authCode, loginStateID)
	if err != nil {
		t.Fatalf("sendFinishLogin(s, cfg, h, %s, %s, %s) failed: %v", idpName, authCode, loginStateID, err)
	}

	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("resp.StatusCode wants %d got %d", http.StatusTemporaryRedirect, resp.StatusCode)
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
		t.Errorf("AcceptLoginReq.Context[%s] in wrong type", hydra.StateIDKey)
	}

	state := &cpb.AuthTokenState{}
	err = s.store.Read(storage.AuthTokenStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, state)
	if err != nil {
		t.Fatalf("read AuthTokenState failed: %v", err)
	}

	if state.Provider != idpName {
		t.Errorf("state.Provider wants %s got %s", idpName, state.Provider)
	}
	loginHint := idpName + ":" + persona
	if state.LoginHint != loginHint {
		t.Errorf("state.LoginHint wants %s got %s", loginHint, state.LoginHint)
	}
	if *h.AcceptLoginReq.Subject != state.Subject {
		t.Errorf("subject send to hydra and subject in state should be equals. got %s, %s", *h.AcceptLoginReq.Subject, state.Subject)
	}
}

func TestFinishLogin_Hydra_Invalid(t *testing.T) {
	s, cfg, h, _, err := setupHydraTest()
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
		code   string
		state  string
		status int
	}{
		{
			name:   "invalid idp",
			idp:    "invalid",
			code:   authCode,
			state:  loginStateID,
			status: http.StatusUnauthorized,
		},
		{
			name:   "invalid auth_code",
			idp:    idpName,
			code:   "invalid",
			state:  loginStateID,
			status: http.StatusUnauthorized,
		},
		{
			name:  "invalid state",
			idp:   idpName,
			code:  authCode,
			state: "invalid",
			// TODO: this case should also consider StatusUnauthorized.
			status: http.StatusInternalServerError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := sendFinishLogin(s, cfg, h, tc.idp, tc.code, tc.state)
			if err != nil {
				t.Fatalf("sendFinishLogin(s, cfg, h, %s, %s, %s) failed: %v", tc.idp, tc.code, tc.state, err)
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

func sendAcceptInformationRelease(s *Service, cfg *pb.IcConfig, h *fakehydra.Server, scope, stateID, agree string) (*http.Response, error) {
	// Ensure auth token state exists before request.
	tokState := &cpb.AuthTokenState{
		Realm:            storage.DefaultRealm,
		Scope:            scope,
		ConsentChallenge: consentChallenge,
		Subject:          LoginSubject,
	}

	err := s.store.Write(storage.AuthTokenStateDatatype, storage.DefaultRealm, storage.DefaultUser, authTokenStateID, storage.LatestRev, tokState, nil)
	if err != nil {
		return nil, err
	}

	// Ensure identity exists before request.
	acct := &pb.Account{
		Properties: &pb.AccountProperties{Subject: LoginSubject},
		State:      "ACTIVE",
	}
	err = s.store.Write(storage.AccountDatatype, storage.DefaultRealm, storage.DefaultUser, LoginSubject, storage.LatestRev, acct, nil)
	if err != nil {
		return nil, err
	}

	// Clear fakehydra server and set reject response.
	h.Clear()
	h.AcceptConsentResp = &hydraapi.RequestHandlerResponse{RedirectTo: hydraURL}
	h.RejectConsentResp = &hydraapi.RequestHandlerResponse{RedirectTo: hydraURL}

	// Send Request.
	query := fmt.Sprintf("?agree=%s&state=%s", agree, stateID)
	u := "https://" + domain + acceptInformationReleasePath + query
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, u, nil)
	s.Handler.ServeHTTP(w, r)

	return w.Result(), nil
}

func TestAcceptInformationRelease_Hydra_Accept(t *testing.T) {
	s, cfg, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	const scope = "openid profile"

	resp, err := sendAcceptInformationRelease(s, cfg, h, scope, authTokenStateID, agree)
	if err != nil {
		t.Fatalf("sendAcceptInformationRelease(s, cfg, h, %s, %s, %s) failed: %v", scope, authTokenStateID, agree, err)
	}

	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("resp.StatusCode wants %d got %d", http.StatusTemporaryRedirect, resp.StatusCode)
	}

	if l := resp.Header.Get("Location"); l != hydraURL {
		t.Errorf("resp.Location wants %s got %s", hydraURL, l)
	}

	if h.RejectConsentReq != nil {
		t.Errorf("RejectConsentReq wants nil got %v", h.RejectConsentReq)
	}

	if diff := cmp.Diff(h.AcceptConsentReq.GrantedScope, strings.Split(scope, " ")); len(diff) != 0 {
		t.Errorf("AcceptConsentReq.GrantedScope wants %s got %v", scope, h.AcceptConsentReq.GrantedScope)
	}

	email, ok := h.AcceptConsentReq.Session.IDToken["email"].(string)
	if !ok {
		t.Fatalf("Email in id token in wrong type")
	}

	wantEmail := LoginSubject + "@" + domain
	if email != wantEmail {
		t.Errorf("Email in id token wants %s got %s", wantEmail, email)
	}
}

func TestAcceptInformationRelease_Hydra_Accept_Scoped(t *testing.T) {
	s, cfg, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	const scope = "openid"

	resp, err := sendAcceptInformationRelease(s, cfg, h, scope, authTokenStateID, agree)
	if err != nil {
		t.Fatalf("sendAcceptInformationRelease(s, cfg, h, %s, %s, %s) failed: %v", scope, authTokenStateID, agree, err)
	}

	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("resp.StatusCode wants %d got %d", http.StatusTemporaryRedirect, resp.StatusCode)
	}

	if l := resp.Header.Get("Location"); l != hydraURL {
		t.Errorf("resp.Location wants %s got %s", hydraURL, l)
	}

	if h.RejectConsentReq != nil {
		t.Errorf("RejectConsentReq wants nil got %v", h.RejectConsentReq)
	}

	if diff := cmp.Diff(h.AcceptConsentReq.GrantedScope, strings.Split(scope, " ")); len(diff) != 0 {
		t.Errorf("AcceptConsentReq.GrantedScope wants %s got %v", scope, h.AcceptConsentReq.GrantedScope)
	}

	if _, ok := h.AcceptConsentReq.Session.IDToken["email"]; ok {
		t.Fatalf("Email in id token should not exists")
	}
}

func TestAcceptInformationRelease_Hydra_Reject(t *testing.T) {
	s, cfg, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	const scope = "openid profile"

	resp, err := sendAcceptInformationRelease(s, cfg, h, scope, authTokenStateID, deny)
	if err != nil {
		t.Fatalf("sendAcceptInformationRelease(s, cfg, h, %s, %s, %s) failed: %v", scope, authTokenStateID, deny, err)
	}

	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("resp.StatusCode wants %d got %d", http.StatusTemporaryRedirect, resp.StatusCode)
	}

	if l := resp.Header.Get("Location"); l != hydraURL {
		t.Errorf("resp.Location wants %s got %s", hydraURL, l)
	}

	if h.AcceptConsentReq != nil {
		t.Errorf("AcceptConsentReq wants nil got %v", h.RejectConsentReq)
	}

	if h.RejectConsentReq == nil {
		t.Errorf("RejectConsentReq got nil")
	}
}

func TestAcceptInformationRelease_Hydra_InvalidState(t *testing.T) {
	s, cfg, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	const scope = "openid profile"

	resp, err := sendAcceptInformationRelease(s, cfg, h, scope, "invalid", agree)
	if err != nil {
		t.Fatalf("sendAcceptInformationRelease(s, cfg, h, %s, 'invalid', %s) failed: %v", scope, agree, err)
	}

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("resp.StatusCode wants %d got %d", http.StatusInternalServerError, resp.StatusCode)
	}

	if h.AcceptConsentReq != nil {
		t.Errorf("AcceptConsentReq wants nil got %v", h.AcceptConsentReq)
	}

	if h.RejectConsentReq != nil {
		t.Errorf("RejectConsentReq wants nil got %v", h.RejectConsentReq)
	}
}

func sendClientsGet(t *testing.T, pname, clientName, clientID string, s *Service, iss *fakeoidcissuer.Server) *http.Response {
	t.Helper()

	var p *cpb.TestPersona
	if iss.Config() != nil {
		p = iss.Config().TestPersonas[pname]
	}

	tok, _, err := persona.NewAccessToken(pname, oidcIssuer, clientID, noScope, p)
	if err != nil {
		t.Fatalf("persona.NewAccessToken(%q, %q, _, _) failed: %v", pname, oidcIssuer, err)
	}

	path := strings.ReplaceAll(clientPath, "{realm}", "test")
	path = strings.ReplaceAll(path, "{name}", clientName)
	q := url.Values{"client_id": []string{clientID}}
	h := http.Header{"Authorization": []string{"Bearer " + string(tok)}}
	return testhttp.SendTestRequest(t, s.Handler, http.MethodGet, path, q, nil, h)
}

func TestClients_Get(t *testing.T) {
	s, cfg, _, iss, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientName := "test_client"
	pname := "non-admin"
	cli := cfg.Clients[clientName]

	resp := sendClientsGet(t, pname, clientName, cli.ClientId, s, iss)

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
	s, _, _, iss, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	tests := []struct {
		name       string
		clientID   string
		clientName string
		status     int
	}{
		{
			name:       "client not exists",
			clientID:   testClientID,
			clientName: "invalid",
			status:     http.StatusNotFound,
		},
		{
			name:       "client id and client name not match",
			clientID:   testClientID,
			clientName: "test_client2",
			status:     http.StatusNotFound,
		},
		{
			name:       "client id empty",
			clientName: "test_client2",
			status:     http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pname := "non-admin"

			resp := sendClientsGet(t, pname, tc.clientName, tc.clientID, s, iss)

			if resp.StatusCode != tc.status {
				t.Errorf("resp.StatusCode = %d, wants %d", resp.StatusCode, tc.status)
			}
		})
	}
}

func sendConfigClientsGet(t *testing.T, pname, clientName, clientID string, s *Service, iss *fakeoidcissuer.Server) *http.Response {
	t.Helper()

	var p *cpb.TestPersona
	if iss.Config() != nil {
		p = iss.Config().TestPersonas[pname]
	}

	tok, _, err := persona.NewAccessToken(pname, oidcIssuer, clientID, noScope, p)
	if err != nil {
		t.Fatalf("persona.NewAccessToken(%q, %q, _, _) failed: %v", pname, oidcIssuer, err)
	}

	path := strings.ReplaceAll(configClientsPath, "{realm}", "test")
	path = strings.ReplaceAll(path, "{name}", clientName)
	q := url.Values{"client_id": []string{clientID}}
	h := http.Header{"Authorization": []string{"Bearer " + string(tok)}}
	return testhttp.SendTestRequest(t, s.Handler, http.MethodGet, path, q, nil, h)
}

func TestConfigClients_Get(t *testing.T) {
	s, cfg, _, iss, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientName := "test_client"
	pname := "admin"
	cli := cfg.Clients[clientName]

	resp := sendConfigClientsGet(t, pname, clientName, cli.ClientId, s, iss)

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
	s, _, _, iss, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	tests := []struct {
		name       string
		persona    string
		clientID   string
		clientName string
		status     int
	}{
		{
			name:       "client not exists",
			persona:    "admin",
			clientID:   testClientID,
			clientName: "invalid",
			status:     http.StatusNotFound,
		},
		{
			name:       "client id empty",
			persona:    "admin",
			clientName: "test_client2",
			// TODO: should fix after integrated hydra client id.
			status: http.StatusOK,
		},
		{
			name:       "not admin",
			persona:    "non-admin",
			clientID:   testClientID,
			clientName: "test_client",
			status:     http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := sendConfigClientsGet(t, tc.persona, tc.clientName, tc.clientID, s, iss)

			if resp.StatusCode != tc.status {
				t.Errorf("resp.StatusCode = %d, wants %d", resp.StatusCode, tc.status)
			}
		})
	}
}

func diffOfHydraClientIgnoreClientIDAndSecret(c1 *hydraapi.Client, c2 *hydraapi.Client) string {
	return cmp.Diff(c1, c2, cmpopts.IgnoreFields(hydraapi.Client{}, "ClientID", "Secret"), cmpopts.IgnoreUnexported(strfmt.DateTime{}))
}

func sendConfigClientsCreate(t *testing.T, pname, clientName, clientID string, cli *cpb.Client, s *Service, iss *fakeoidcissuer.Server) *http.Response {
	t.Helper()

	var p *cpb.TestPersona
	if iss.Config() != nil {
		p = iss.Config().TestPersonas[pname]
	}

	tok, _, err := persona.NewAccessToken(pname, oidcIssuer, clientID, noScope, p)
	if err != nil {
		t.Fatalf("persona.NewAccessToken(%q, %q, _, _) failed: %v", pname, oidcIssuer, err)
	}

	m := jsonpb.Marshaler{}
	var buf bytes.Buffer
	if err := m.Marshal(&buf, &cpb.ConfigClientRequest{Item: cli}); err != nil {
		t.Fatal(err)
	}

	path := strings.ReplaceAll(configClientsPath, "{realm}", "test")
	path = strings.ReplaceAll(path, "{name}", clientName)
	q := url.Values{"client_id": []string{clientID}}
	h := http.Header{"Authorization": []string{"Bearer " + string(tok)}}
	return testhttp.SendTestRequest(t, s.Handler, http.MethodPost, path, q, &buf, h)
}

func TestConfigClients_Create_Success(t *testing.T) {
	s, _, h, iss, err := setupHydraTest()
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

	resp := sendConfigClientsCreate(t, pname, clientName, cli.ClientId, cli, s, iss)
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
	s, _, h, iss, err := setupHydraTest()
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

	resp := sendConfigClientsCreate(t, pname, clientName, cli.ClientId, cli, s, iss)
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
	s, _, h, iss, err := setupHydraTest()
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
		clientID   string
		clientName string
		client     *cpb.Client
		status     int
	}{
		{
			name:       "client exists",
			persona:    "admin",
			clientID:   testClientID,
			clientName: "test_client",
			client:     cli,
			status:     http.StatusConflict,
		},
		{
			name:       "not admin",
			persona:    "non-admin",
			clientID:   testClientID,
			clientName: clientName,
			client:     cli,
			status:     http.StatusForbidden,
		},
		{
			name:       "no redirect",
			persona:    "admin",
			clientID:   testClientID,
			clientName: clientName,
			client:     &cpb.Client{Ui: cli.Ui},
			status:     http.StatusBadRequest,
		},
		{
			name:       "no ui",
			persona:    "admin",
			clientID:   testClientID,
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

			resp := sendConfigClientsCreate(t, tc.persona, tc.clientName, tc.clientID, tc.client, s, iss)

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
	s, _, h, iss, err := setupHydraTest()
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

	resp := sendConfigClientsCreate(t, "admin", clientName, testClientID, cli, s, iss)

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

func sendConfigClientsUpdate(t *testing.T, pname, clientName, clientID string, cli *cpb.Client, s *Service, iss *fakeoidcissuer.Server) *http.Response {
	t.Helper()

	var p *cpb.TestPersona
	if iss.Config() != nil {
		p = iss.Config().TestPersonas[pname]
	}

	tok, _, err := persona.NewAccessToken(pname, oidcIssuer, clientID, noScope, p)
	if err != nil {
		t.Fatalf("persona.NewAccessToken(%q, %q, _, _) failed: %v", pname, oidcIssuer, err)
	}

	m := jsonpb.Marshaler{}
	var buf bytes.Buffer
	if err := m.Marshal(&buf, &cpb.ConfigClientRequest{Item: cli}); err != nil {
		t.Fatal(err)
	}

	path := strings.ReplaceAll(configClientsPath, "{realm}", "test")
	path = strings.ReplaceAll(path, "{name}", clientName)
	q := url.Values{"client_id": []string{clientID}}
	h := http.Header{"Authorization": []string{"Bearer " + string(tok)}}
	return testhttp.SendTestRequest(t, s.Handler, http.MethodPatch, path, q, &buf, h)
}

func TestConfigClients_Update_Success(t *testing.T) {
	s, cfg, h, iss, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientName := "test_client"

	before := cfg.Clients[clientName]

	sec, err := s.loadSecrets(nil)
	if err != nil {
		t.Fatalf("s.loadSecrets() failed: %v", err)
	}
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

	resp := sendConfigClientsUpdate(t, pname, clientName, cli.ClientId, cli, s, iss)
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
	s, _, h, iss, err := setupHydraTest()
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

	resp := sendConfigClientsUpdate(t, pname, clientName, cli.ClientId, cli, s, iss)
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
	s, cfg, h, iss, err := setupHydraTest()
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
		clientID   string
		clientName string
		status     int
	}{
		{
			name:       "client not exists",
			persona:    "admin",
			clientID:   testClientID,
			clientName: "invalid",
			status:     http.StatusNotFound,
		},
		{
			name:       "not admin",
			persona:    "non-admin",
			clientID:   testClientID,
			clientName: clientName,
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

			resp := sendConfigClientsUpdate(t, tc.persona, tc.clientName, tc.clientID, cli, s, iss)

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
	s, cfg, h, iss, err := setupHydraTest()
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

	resp := sendConfigClientsUpdate(t, "admin", clientName, testClientID, cli, s, iss)

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

func sendConfigClientsDelete(t *testing.T, pname, clientName, clientID string, s *Service, iss *fakeoidcissuer.Server) *http.Response {
	t.Helper()

	var p *cpb.TestPersona
	if iss.Config() != nil {
		p = iss.Config().TestPersonas[pname]
	}

	tok, _, err := persona.NewAccessToken(pname, oidcIssuer, clientID, noScope, p)
	if err != nil {
		t.Fatalf("persona.NewAccessToken(%q, %q, _, _) failed: %v", pname, oidcIssuer, err)
	}

	path := strings.ReplaceAll(configClientsPath, "{realm}", "test")
	path = strings.ReplaceAll(path, "{name}", clientName)
	q := url.Values{"client_id": []string{clientID}}
	h := http.Header{"Authorization": []string{"Bearer " + string(tok)}}
	return testhttp.SendTestRequest(t, s.Handler, http.MethodDelete, path, q, nil, h)
}

func TestConfigClients_Delete_Success(t *testing.T) {
	s, _, _, iss, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientName := "test_client"

	pname := "admin"

	resp := sendConfigClientsDelete(t, pname, clientName, testClientID, s, iss)

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
	if _, ok := sec.ClientSecrets[testClientID]; ok {
		t.Errorf("client secret should not exist in storage")
	}
}

func TestConfigClients_Delete_Error(t *testing.T) {
	s, cfg, h, iss, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientName := "test_client"

	tests := []struct {
		name       string
		persona    string
		clientID   string
		clientName string
		status     int
	}{
		{
			name:       "client not exists",
			persona:    "admin",
			clientID:   testClientID,
			clientName: "invalid",
			status:     http.StatusNotFound,
		},
		{
			name:       "not admin",
			persona:    "non-admin",
			clientID:   testClientID,
			clientName: clientName,
			status:     http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h.Clear()

			resp := sendConfigClientsDelete(t, tc.persona, tc.clientName, tc.clientID, s, iss)

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
	s, cfg, h, iss, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	clientName := "test_client"

	h.DeleteClientErr = &hydraapi.GenericError{Code: http.StatusServiceUnavailable}

	resp := sendConfigClientsDelete(t, "admin", clientName, testClientID, s, iss)

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
