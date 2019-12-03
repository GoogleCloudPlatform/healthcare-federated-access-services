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

// Package credtest contains test helpers for testing endpoints client credentials requirement.
package credtest

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test"
)

// Requirement is the client credentials requirement.
type Requirement struct {
	ClientID     bool
	ClientSecret bool
}

func pathsInRouter(t *testing.T, r *mux.Router) []string {
	t.Helper()

	var paths []string

	r.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		path, err := route.GetPathTemplate()
		if err != nil {
			t.Fatalf("GetPathTemplate() failed: %v", err)
		}
		paths = append(paths, path)

		return nil
	})

	return paths
}

// RequestWithClientCreds builds request to test client credentials.
func RequestWithClientCreds(t *testing.T, domainURL, path, clientID, clientSecret string) *http.Request {
	t.Helper()

	p := strings.ReplaceAll(path, "{realm}", "test")
	p = strings.ReplaceAll(p, "{", "")
	p = strings.ReplaceAll(p, "}", "")

	u, err := url.Parse(domainURL + p)
	if err != nil {
		t.Fatalf("url.Parse(%s) failed: %v", domainURL+p, err)
	}

	q := u.Query()

	if len(clientID) > 0 {
		q.Add("client_id", clientID)
		if len(clientSecret) > 0 {
			q.Add("client_secret", clientSecret)
		}
	}

	u.RawQuery = q.Encode()

	r := httptest.NewRequest(http.MethodGet, u.String(), nil)
	r.ParseForm()

	return r
}

// PathClientCreds returns all client credentials in router.
func PathClientCreds(t *testing.T, r *mux.Router, domainURL string, f func(*http.Request) error) map[string]Requirement {
	t.Helper()

	m := make(map[string]Requirement)

	paths := pathsInRouter(t, r)

	for _, path := range paths {
		noCredentials := RequestWithClientCreds(t, domainURL, path, "", "")
		clientIDOnly := RequestWithClientCreds(t, domainURL, path, test.TestClientID, "")

		c := Requirement{
			ClientID:     f(noCredentials) != nil,
			ClientSecret: f(clientIDOnly) != nil,
		}

		m[path] = c
	}

	return m
}
