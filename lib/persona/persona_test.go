// Copyright 2021 Google LLC.
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

package persona

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"gopkg.in/square/go-jose.v2" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/globalflags" /* copybara-comment: globalflags */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
)

const (
	brokerURL = "https://oidc.example.com"
)

func TestWellKnown(t *testing.T) {
	o := setup(t)

	r := httptest.NewRequest(http.MethodGet, brokerURL+oidcConfiguarePath, nil)
	w := httptest.NewRecorder()
	o.Handler.ServeHTTP(w, r)

	resp := w.Result()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status code = %d, wants %d", http.StatusOK, resp.StatusCode)
	}

	wantContentType := "application/json"
	if got := resp.Header.Get("Content-Type"); got != wantContentType {
		t.Errorf("response Header Content-Type = %s, wants %s", got, wantContentType)
	}

	got := &cpb.OidcConfig{}
	want := &cpb.OidcConfig{
		AuthEndpoint:     brokerURL + "/authorize",
		Issuer:           brokerURL,
		JwksUri:          brokerURL + "/.well-known/jwks",
		TokenEndpoint:    brokerURL + "/token",
		UserinfoEndpoint: brokerURL + "/userinfo",
	}

	if err := httputils.DecodeJSONPB(resp.Body, got); err != nil {
		t.Fatalf("httputils.DecodeJSONPB() failed: %v", err)
	}

	if d := cmp.Diff(want, got, protocmp.Transform()); len(d) > 0 {
		t.Errorf("response (-want, +got): %s", d)
	}
}

func TestJWKS(t *testing.T) {
	globalflags.LocalSignerAlgorithm = "RS384"
	t.Cleanup(func() {
		globalflags.LocalSignerAlgorithm = "RS256"
	})
	o := setup(t)

	r := httptest.NewRequest(http.MethodGet, brokerURL+oidcJwksPath, nil)
	w := httptest.NewRecorder()
	o.Handler.ServeHTTP(w, r)

	resp := w.Result()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status code = %d, wants %d", http.StatusOK, resp.StatusCode)
	}

	wantContentType := "application/json"
	if got := resp.Header.Get("Content-Type"); got != wantContentType {
		t.Errorf("response Header Content-Type = %s, wants %s", got, wantContentType)
	}

	got := &jose.JSONWebKeySet{}
	want := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:                         testkeys.PersonaBrokerKey.Public,
				Algorithm:                   "RS384",
				Use:                         "sig",
				KeyID:                       string(testkeys.PersonaBroker),
				Certificates:                []*x509.Certificate{},
				CertificateThumbprintSHA256: []byte{},
			},
		},
	}

	if err := httputils.DecodeJSON(resp.Body, got); err != nil {
		t.Fatalf("httputils.DecodeJSON() failed: %v", err)
	}

	if d := cmp.Diff(want, got); len(d) > 0 {
		t.Errorf("response (-want, +got): %s", d)
	}
}

func setup(t *testing.T) *Server {
	t.Helper()
	broker, err := NewBroker(brokerURL, &testkeys.PersonaBrokerKey, "dam", "testdata/config", false)
	if err != nil {
		t.Fatalf("NewBroker() failed: %v", err)
	}
	return broker
}
