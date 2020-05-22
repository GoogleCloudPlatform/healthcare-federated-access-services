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

package httputils

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */
)

func TestNewPageHandler(t *testing.T) {
	w := NewFakeWriter()
	page := "some HTML page"
	csp := CSPFromString("a b")

	h := NewPageHandler(page, csp)
	h(w, &http.Request{})

	got := w
	want := &FakeWriter{
		Headers: http.Header{
			"Content-Security-Policy": {
				"a b;default-src 'self';font-src https://fonts.gstatic.com;frame-ancestors 'self';img-src 'self' data: http://icon-library.com;script-src 'self' https://ajax.googleapis.com https://code.getmdl.io;style-src 'self' https://code.getmdl.io https://fonts.googleapis.com",
			},
			"X-Frame-Options": {"SAMEORIGIN"},
			"Content-Type":    {"text/html"},
		},
		Body: page,
		Code: 0,
	}
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("NewPageHandler() returned diff (-want +got):\n%s", diff)
	}
}

func Test_LivenessCheckHandler(t *testing.T) {
	w := httptest.NewRecorder()
	LivenessCheckHandler(w, &http.Request{})

	got := w.Result().StatusCode

	if got != http.StatusOK {
		t.Errorf("status = %d wants %d", got, http.StatusOK)
	}
}
