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

package cli

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/gorilla/mux" /* copybara-comment */
	"github.com/golang/protobuf/jsonpb" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/auth" /* copybara-comment: auth */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/handlerfactory" /* copybara-comment: handlerfactory */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/kms/fakeencryption" /* copybara-comment: fakeencryption */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/permissions" /* copybara-comment: permissions */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakeoidcissuer" /* copybara-comment: fakeoidcissuer */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test" /* copybara-comment: test */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */

	glog "github.com/golang/glog" /* copybara-comment */
	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
)

const (
	cliAcceptPath   = "/test/cli/accept"
	cliAuthPath     = "/test/cli/auth/{name}"
	cliRegisterPath = "/test/cli/register/{name}"
	domainURL       = "https://cli.example.com"
	hydraPublicURL  = "https://hydra.example.com/"
	hydraAuthURL    = hydraPublicURL + "authorize"
	hydraTokenURL   = hydraPublicURL + "token"
)

func TestCLIRegister(t *testing.T) {
	store := storage.NewMemoryStorage("dam", "testdata/config")
	server, err := fakeoidcissuer.New(hydraPublicURL, &testkeys.PersonaBrokerKey, "dam", "testdata/config", false)
	if err != nil {
		t.Fatalf("fakeoidcissuer.New(%q, _, _) failed: %v", hydraPublicURL, err)
	}
	s := serviceNew(t, store, server.Client())
	tests := []test.HandlerTest{
		{
			Method: "POST",
			Path:   "/test/cli/register/auto",
			Params: `email=admin@faculty.example.edu`,
			Output: `*{"id":"*","email":"admin@faculty.example.edu","scope":"openid profile email offline","authUrl":"https://cli.example.com/test/cli/auth/*","createdAt":"*","expiresAt":"*","secret":"*"}*`,
			Status: http.StatusOK,
		},
		{
			Method: "POST",
			Path:   "/test/cli/register/be0feb4e-8251-4a53-8903-6484a10d4f78",
			Params: `email=admin@faculty.example.edu`,
			Output: `*{"id":"be0feb4e-8251-4a53-8903-6484a10d4f78","email":"admin@faculty.example.edu","scope":"openid profile email offline","authUrl":"https://cli.example.com/test/cli/auth/be0feb4e-8251-4a53-8903-6484a10d4f78","createdAt":"*","expiresAt":"*","secret":"*"}*`,
			Status: http.StatusOK,
		},
		{
			Method: "GET",
			Path:   "/test/cli/register/be0feb4e-8251-4a53-8903-6484a10d4f78",
			Output: `*login_secret*`,
			Status: http.StatusBadRequest,
		},
	}
	test.HandlerTests(t, s.Handler, tests, hydraPublicURL, nil)
}

func TestClIFlow_Success(t *testing.T) {
	email := "admin@faculty.example.edu"
	tokenOutput := `*{"id":"1a4f6c82-d8a7-433b-9916-12e365efc971","email":"` + email + `","clientId":"*","scope":"*","createdAt":"*","expiresAt":"*","accessToken":"ey*","refreshToken":"*","userProfile":{*"family_name":"*","given_name":"*","name":"*",*"subject":"admin"*}}*`
	tokenStatus := http.StatusOK
	if err := cliFlow(t, email, tokenOutput, tokenStatus); err != nil {
		t.Fatalf("cliFlow(t, %q, _, %d) failed: %v", email, tokenStatus, err)
	}
}

func TestClIFlow_EmailMismatch(t *testing.T) {
	email := "bad_admin@faculty.example.edu"
	tokenOutput := `*bad_admin@faculty.example.edu*`
	tokenStatus := http.StatusUnauthorized
	if err := cliFlow(t, email, tokenOutput, tokenStatus); err != nil {
		t.Fatalf("cliFlow(t, %q, _, %d) failed: %v", email, tokenStatus, err)
	}
}

func cliFlow(t *testing.T, email, tokenOutput string, tokenStatus int) error {
	t.Helper()

	store := storage.NewMemoryStorage("dam", "testdata/config")
	server, err := fakeoidcissuer.New(hydraPublicURL, &testkeys.PersonaBrokerKey, "dam", "testdata/config", false)
	if err != nil {
		return fmt.Errorf("fakeoidcissuer.New(%q, _, _) failed: %v", hydraPublicURL, err)
	}
	s := serviceNew(t, store, server.Client())

	// Step 1: cli/register and initiate cli/auth.
	regReq := []test.HandlerTest{
		{
			Name:   "register",
			Method: "POST",
			Path:   "/test/cli/register/1a4f6c82-d8a7-433b-9916-12e365efc971",
			Params: "email=" + email,
			Output: `*{"id":"1a4f6c82-d8a7-433b-9916-12e365efc971","email":"` + email + `","scope":"openid profile email offline","authUrl":"https://cli.example.com/test/cli/auth/1a4f6c82-d8a7-433b-9916-12e365efc971","createdAt":"*","expiresAt":"*","secret":"*"}*`,
			Status: http.StatusOK,
		},
		{
			Name:   "auth",
			Method: "GET",
			Path:   "/test/cli/auth/1a4f6c82-d8a7-433b-9916-12e365efc971",
			Output: `*https://hydra.example.com/authorize?client_id=*grant_type=authorization_code*redirect_uri=*response_type=code*scope=openid+profile+email+offline*state=1a4f6c82-d8a7-433b-9916-12e365efc971*`,
			Status: http.StatusSeeOther,
		},
	}
	regResp := test.HandlerTests(t, s.Handler, regReq, hydraPublicURL, nil)["register"]
	if regResp == "" {
		return fmt.Errorf("register failed (see errors above)")
	}
	reg := &cpb.CliState{}
	if err = jsonpb.UnmarshalString(regResp, reg); err != nil {
		return fmt.Errorf("register jsonpb.UnmarshalString(%q, reg) failed: %v", regResp, err)
	}
	t.Logf("registration: %+v", reg)

	// Step 2: Accept.
	code := "admin," + test.TestClientID
	acceptReq := []test.HandlerTest{
		{
			Name:   "accept",
			Method: "GET",
			Path:   "/test/cli/accept",
			Params: fmt.Sprintf("code=%s&state=%s&nonce=%s", code, reg.Id, reg.Nonce),
			Output: `*success*`,
			Status: http.StatusOK,
		},
	}
	test.HandlerTests(t, s.Handler, acceptReq, hydraPublicURL, nil)

	// Step 3: Get tokens.
	tokReq := []test.HandlerTest{
		{
			Name:   "tokens",
			Method: "GET",
			Path:   "/test/cli/register/1a4f6c82-d8a7-433b-9916-12e365efc971",
			Params: fmt.Sprintf("login_secret=%s", reg.Secret),
			Output: tokenOutput,
			Status: tokenStatus,
		},
	}
	test.HandlerTests(t, s.Handler, tokReq, hydraPublicURL, nil)
	return nil
}

type service struct {
	Handler *mux.Router
}

func serviceNew(t *testing.T, store storage.Store, client *http.Client) *service {
	checker := auth.NewChecker(nil, hydraPublicURL, permissions.New(store), func() (map[string]string, error) {
		return map[string]string{test.TestClientID: test.TestClientSecret}, nil
	}, func(id *ga4gh.Identity) *ga4gh.Identity { return id })

	crypt := fakeencryption.New()

	r := mux.NewRouter()
	r.HandleFunc(cliRegisterPath, auth.MustWithAuth(handlerfactory.MakeHandler(store, RegisterFactory(store, cliRegisterPath, crypt, domainURL+cliAuthPath, hydraPublicURL, hydraAuthURL, hydraTokenURL, cliAcceptPath, client)), checker, auth.RequireClientIDAndSecret))
	r.HandleFunc(cliAuthPath, auth.MustWithAuth(NewAuthHandler(store).Handle, checker, auth.RequireNone)).Methods(http.MethodGet)
	accept, err := NewAcceptHandler(store, crypt, "/test")
	if err != nil {
		glog.Fatalf("NewAcceptHandler() failed: %v", err)
	}
	r.HandleFunc(cliAcceptPath, auth.MustWithAuth(accept.Handle, checker, auth.RequireNone)).Methods(http.MethodGet)

	return &service{
		Handler: r,
	}
}
