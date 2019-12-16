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
	"context"
	"testing"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/kms/fakeencryption" /* copybara-comment: fakeencryption */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/credtest" /* copybara-comment: credtest */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakeoidcissuer" /* copybara-comment: fakeoidcissuer */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test" /* copybara-comment: test */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */
)

var paths = map[string]credtest.Requirement{
	infoPath:                     {ClientID: false, ClientSecret: false},
	realmPath:                    {ClientID: true, ClientSecret: true},
	clientPath:                   {ClientID: true, ClientSecret: true},
	configPath:                   {ClientID: true, ClientSecret: true},
	configHistoryPath:            {ClientID: true, ClientSecret: true},
	configHistoryRevisionPath:    {ClientID: true, ClientSecret: true},
	configResetPath:              {ClientID: true, ClientSecret: true},
	configIdentityProvidersPath:  {ClientID: true, ClientSecret: true},
	configClientsPath:            {ClientID: true, ClientSecret: true},
	configOptionsPath:            {ClientID: true, ClientSecret: true},
	identityProvidersPath:        {ClientID: true, ClientSecret: false},
	translatorsPath:              {ClientID: true, ClientSecret: false},
	tokenPath:                    {ClientID: true, ClientSecret: true},
	tokenMetadataPath:            {ClientID: true, ClientSecret: true},
	adminTokenMetadataPath:       {ClientID: true, ClientSecret: true},
	revocationPath:               {ClientID: true, ClientSecret: true},
	loginPagePath:                {ClientID: true, ClientSecret: false},
	loginPath:                    {ClientID: false, ClientSecret: false},
	acceptLoginPath:              {ClientID: false, ClientSecret: false},
	finishLoginPath:              {ClientID: false, ClientSecret: false},
	acceptInformationReleasePath: {ClientID: false, ClientSecret: false},
	testPath:                     {ClientID: false, ClientSecret: false},
	tokenFlowTestPath:            {ClientID: false, ClientSecret: false},
	scimMePath:                   {ClientID: true, ClientSecret: true},
	scimUsersPath:                {ClientID: true, ClientSecret: true},
	scimUserPath:                 {ClientID: true, ClientSecret: true},
	authorizePath:                {ClientID: true, ClientSecret: false},
	accountPath:                  {ClientID: true, ClientSecret: true},
	accountSubjectPath:           {ClientID: true, ClientSecret: true},
	adminClaimsPath:              {ClientID: true, ClientSecret: true},
	oidcConfiguarePath:           {ClientID: false, ClientSecret: false},
	oidcJwksPath:                 {ClientID: false, ClientSecret: false},
	oidcUserInfoPath:             {ClientID: false, ClientSecret: false},
	hydraLoginPath:               {ClientID: false, ClientSecret: false},
	hydraConsentPath:             {ClientID: false, ClientSecret: false},
	hydraTestPage:                {ClientID: false, ClientSecret: false},
	"/tokens":                    {ClientID: true, ClientSecret: true},
	"/tokens/":                   {ClientID: true, ClientSecret: true},
	"/consents":                  {ClientID: true, ClientSecret: true},
	"/consents/":                 {ClientID: true, ClientSecret: true},
	staticFilePath:               {ClientID: false, ClientSecret: false},
}

func setup(t *testing.T) *Service {
	store := storage.NewMemoryStorage("ic-min", "testdata/config")
	server, err := fakeoidcissuer.New(oidcIssuer, &testkeys.PersonaBrokerKey, "dam-min", "testdata/config")
	if err != nil {
		t.Fatalf("fakeoidcissuer.New() failed: %v", err)
	}
	ctx := server.ContextWithClient(context.Background())
	crypt := fakeencryption.New()
	s := NewService(ctx, domain, domain, hydraAdminURL, store, crypt, notUseHydra)
	return s
}

func Test_checkClientCreds(t *testing.T) {
	s := setup(t)

	got := credtest.PathClientCreds(t, s.Handler.Handler, s.getDomainURL(), s.checkClientCreds)
	if diff := cmp.Diff(paths, got); len(diff) > 0 {
		t.Errorf("PathClientCredentials (-want, +got): %s", diff)
	}
}

func Test_checkClientCredsWithSecret(t *testing.T) {
	s := setup(t)

	for p := range paths {
		r := credtest.RequestWithClientCreds(t, s.getDomainURL(), p, test.TestClientID, test.TestClientSecret)
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
		r := credtest.RequestWithClientCreds(t, s.getDomainURL(), p, test.TestClientID, "invalid")
		if err := s.checkClientCreds(r); err == nil {
			t.Errorf("checkClientCreds(%s) should failed with invalid secret", p)
		}
	}
}
