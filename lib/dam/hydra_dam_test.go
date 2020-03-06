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
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/httptestclient" /* copybara-comment: httptestclient */
)

func TestOAuthToken(t *testing.T) {
	s, f := setupOAuthTokenTest()

	target := "https://example.com/oauth2/token"
	wantTok := "aaa"
	r := httptest.NewRequest(http.MethodPost, target, bytes.NewBufferString("token="+wantTok))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	s.Handler.ServeHTTP(w, r)

	if f.reqURL != target {
		t.Errorf("RequestURI in dest server = %s want %s", f.reqURL, target)
	}
	if f.form.Get("token") != wantTok {
		t.Errorf("form[token] = %s want %s", f.form.Get("token"), wantTok)
	}
}

func setupOAuthTokenTest() (*Service, *fakeHydraPublic) {
	fake := &fakeHydraPublic{}

	store := storage.NewMemoryStorage("dam-min", "testdata/config")
	opts := &Options{
		HTTPClient:             httptestclient.New(fake),
		Domain:                 "test.org",
		ServiceName:            "dam",
		DefaultBroker:          "no-broker",
		Store:                  store,
		Warehouse:              nil,
		UseHydra:               useHydra,
		HydraAdminURL:          hydraAdminURL,
		HydraPublicURL:         hydraPublicURL,
		HydraPublicURLInternal: hydraURLInternal,
		HidePolicyBasis:        true,
		HideRejectDetail:       true,
	}
	s := NewService(opts)

	return s, fake
}

type fakeHydraPublic struct {
	form   url.Values
	reqURL string
}

func (s *fakeHydraPublic) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	s.form = r.PostForm
	s.reqURL = r.RequestURI
}
