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
	"testing"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds" /* copybara-comment: clouds */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/credtest" /* copybara-comment: credtest */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakeoidcissuer" /* copybara-comment: fakeoidcissuer */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test" /* copybara-comment: test */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */
)

var paths = map[string]credtest.Requirement{
	infoPath:                        {ClientID: false, ClientSecret: false},
	clientPath:                      {ClientID: true, ClientSecret: true},
	resourcesPath:                   {ClientID: true, ClientSecret: true},
	resourcePath:                    {ClientID: true, ClientSecret: true},
	viewsPath:                       {ClientID: true, ClientSecret: true},
	flatViewsPath:                   {ClientID: true, ClientSecret: true},
	viewPath:                        {ClientID: true, ClientSecret: true},
	rolesPath:                       {ClientID: true, ClientSecret: true},
	rolePath:                        {ClientID: true, ClientSecret: true},
	testPath:                        {ClientID: true, ClientSecret: true},
	adaptersPath:                    {ClientID: true, ClientSecret: true},
	translatorsPath:                 {ClientID: true, ClientSecret: true},
	damRoleCategoriesPath:           {ClientID: true, ClientSecret: true},
	testPersonasPath:                {ClientID: true, ClientSecret: true},
	processesPath:                   {ClientID: true, ClientSecret: true},
	processPath:                     {ClientID: true, ClientSecret: true},
	loggedInPath:                    {ClientID: false, ClientSecret: false},
	resourceTokensPath:              {ClientID: true, ClientSecret: true},
	configHistoryPath:               {ClientID: true, ClientSecret: true},
	configHistoryRevisionPath:       {ClientID: true, ClientSecret: true},
	configResetPath:                 {ClientID: true, ClientSecret: true},
	configTestPersonasPath:          {ClientID: true, ClientSecret: true},
	configPath:                      {ClientID: true, ClientSecret: true},
	configOptionsPath:               {ClientID: true, ClientSecret: true},
	configResourcePath:              {ClientID: true, ClientSecret: true},
	configViewPath:                  {ClientID: true, ClientSecret: true},
	configTrustedPassportIssuerPath: {ClientID: true, ClientSecret: true},
	configTrustedSourcePath:         {ClientID: true, ClientSecret: true},
	configPolicyPath:                {ClientID: true, ClientSecret: true},
	configClaimDefPath:              {ClientID: true, ClientSecret: true},
	configServiceTemplatePath:       {ClientID: true, ClientSecret: true},
	configTestPersonaPath:           {ClientID: true, ClientSecret: true},
	configClientPath:                {ClientID: true, ClientSecret: true},
	hydraLoginPath:                  {ClientID: false, ClientSecret: false},
	hydraConsentPath:                {ClientID: false, ClientSecret: false},
}

func setup(t *testing.T) *Service {
	t.Helper()
	store := storage.NewMemoryStorage("dam", "testdata/config")
	wh := clouds.NewMockTokenCreator(false)
	server, err := fakeoidcissuer.New(hydraPublicURL, &testkeys.PersonaBrokerKey, "dam", "testdata/config", false)
	if err != nil {
		t.Fatalf("fakeoidcissuer.New() failed: %v", err)
	}
	ctx := server.ContextWithClient(context.Background())
	s := NewService(ctx, "example.com", "no-broker", hydraAdminURL, hydraPublicURL, store, wh, useHydra)
	return s
}

func Test_checkClientCreds(t *testing.T) {
	s := setup(t)

	got := credtest.PathClientCreds(t, s.Handler.Handler, "https://"+s.domainURL, s.checkClientCreds)
	if diff := cmp.Diff(paths, got); len(diff) > 0 {
		t.Errorf("PathClientCredentials (-want, +got): %s", diff)
	}
}

func Test_checkClientCredsWithSecret(t *testing.T) {
	s := setup(t)

	for p := range paths {
		r := credtest.RequestWithClientCreds(t, "https://"+s.domainURL, p, test.TestClientID, test.TestClientSecret)
		if err := s.checkClientCreds(r); err != nil {
			t.Errorf("checkClientCreds(%s) always failed: %v", p, err)
		}
	}
}

func Test_checkClientCredsWithInvalidSecret(t *testing.T) {
	s := setup(t)

	for p, cred := range paths {
		if !cred.ClientSecret {
			continue
		}
		r := credtest.RequestWithClientCreds(t, "https://"+s.domainURL, p, test.TestClientID, "invalid")
		if err := s.checkClientCreds(r); err == nil {
			t.Errorf("checkClientCreds(%s) should failed with invalid secret", p)
		}
	}
}
