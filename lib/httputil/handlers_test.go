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

package httputil

import (
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */
)

func TestNewPageHandler(t *testing.T) {
	w := NewFakeWriter()
	page := "some HTML page"

	h := NewPageHandler(page)
	h(w, &http.Request{})

	got := w
	want := &FakeWriter{
		Headers: http.Header{
			"Access-Control-Allow-Headers": {"Content-Type, Origin, Accept, Authorization, X-Link-Authorization"},
			"Access-Control-Allow-Methods": {"GET,POST,PUT,PATCH,DELETE,OPTIONS"},
			"Access-Control-Allow-Origin":  {"*"},
			"Content-Type":                 {"text/html"},
		},
		Body: page,
		Code: 0,
	}
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("NewPageHandler() returned diff (-want +got):\n%s", diff)
	}
}

func Test_LivenessCheckHandler(t *testing.T) {
	w := NewFakeWriter()
	LivenessCheckHandler(w, &http.Request{})

	got := w
	want := &FakeWriter{
		Headers: http.Header{
			"Access-Control-Allow-Headers": {"Content-Type, Origin, Accept, Authorization, X-Link-Authorization"},
			"Access-Control-Allow-Methods": {"GET,POST,PUT,PATCH,DELETE,OPTIONS"},
			"Access-Control-Allow-Origin":  {"*"},
			"Cache-Control":                {"no-store"},
			"Content-Type":                 {"application/json"},
			"Pragma":                       {"no-cache"},
		},
		Body: livenessPage,
		Code: 0,
	}
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("LivenessCheckHandler() returned diff (-want +got):\n%s", diff)
	}
}
