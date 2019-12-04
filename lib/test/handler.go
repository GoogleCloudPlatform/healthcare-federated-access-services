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

// Package test contains test utility code shared between IC and DAM.
package test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/persona"
	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1"
	dampb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1"
)

const (
	// TestClientID is the client ID for tests.
	TestClientID = "00000000-0000-0000-0000-000000000000"
	// TestClientSecret is the client secret for test client.
	TestClientSecret = "00000000-0000-0000-0000-000000000001"
	// TestIssuerURL is the URL of the fake OIDC Issuer service.
	TestIssuerURL = "https://example.org/oidc"
)

var (
	varRE = regexp.MustCompile(`(\$\((.*?)\))`)
)

// HandlerTest holds the test variables for a service handler test.
type HandlerTest struct {
	Name       string
	Method     string
	Path       string
	Input      string
	Params     string
	IsForm     bool
	Persona    string
	Output     string
	CmpOptions cmp.Options
	Status     int
}

type serviceHandler interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request)
}

// HandlerTests run tests on a service handler.
func HandlerTests(t *testing.T, h serviceHandler, tests []HandlerTest, issuerURL string, cfg *dampb.DamConfig) {
	testOutput := make(map[string]string)
	for _, test := range tests {
		name := test.Name
		if len(name) == 0 {
			name = test.Method + " " + test.Path
		}
		pname := "dr_joe_elixir"
		if len(test.Persona) > 0 {
			pname = test.Persona
		}
		var p *cpb.TestPersona
		if cfg != nil {
			p = cfg.TestPersonas[pname]
		}
		acTok, _, err := persona.NewAccessToken(pname, issuerURL, TestClientID, p)
		if err != nil {
			t.Fatalf("persona.NewAccessToken(%q, %q, _, _) failed: %v", pname, issuerURL, err)
		}
		target := fmt.Sprintf("%s?client_id=%s&client_secret=%s", test.Path, TestClientID, TestClientSecret)
		if len(test.Params) > 0 {
			target += "&" + test.Params
		}
		var Input io.Reader
		varInput := false
		InputStr := test.Input
		if len(test.Input) > 0 {
			for match := varRE.FindStringSubmatch(InputStr); match != nil; match = varRE.FindStringSubmatch(InputStr) {
				varInput = true
				ref := match[2]
				if len(testOutput[ref]) == 0 {
					t.Fatalf("test %q uses %q, but %q must be tested separately earlier in the test list", name, ref, ref)
				}
				InputStr = strings.Replace(InputStr, match[1], testOutput[ref], -1)
			}
			Input = strings.NewReader(InputStr)
		}
		r := httptest.NewRequest(test.Method, target, Input)
		if test.IsForm {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		r.Header.Set("Authorization", "Bearer "+string(acTok))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		Output := w.Body.String()
		testOutput[name] = Output
		hasError := false

		if w.Code != test.Status {
			hasError = true
			t.Errorf("test %q returned wrong status code: got %d want %d", name, w.Code, test.Status)
		}
		if strings.HasPrefix(test.Output, "^") {
			re, err := regexp.Compile(test.Output)
			if err != nil {
				t.Fatalf("test %q cannot compile regexp Output %q: %v", name, test.Output, err)
			}
			if !re.Match([]byte(Output)) {
				hasError = true
				t.Errorf("test %q returned unexpected body: got %q want regexp match of %q", name, Output, test.Output)
			}
		} else if diff := cmp.Diff(test.Output, Output, test.CmpOptions); diff != "" {
			hasError = true
			t.Errorf("test %q returned mismatching body (-want +got):\n%s", name, diff)
		}
		if hasError && varInput {
			t.Logf("test %q Input value was: %s", name, InputStr)
		}
	}
}
