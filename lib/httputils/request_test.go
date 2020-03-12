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
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux" /* copybara-comment */
	"github.com/golang/protobuf/jsonpb" /* copybara-comment */

	dpb "github.com/golang/protobuf/ptypes/duration" /* copybara-comment */
)

func Test_DecodeProtoReq(t *testing.T) {
	m := &dpb.Duration{Seconds: 60}
	b := bytes.NewBuffer(nil)
	if err := (&jsonpb.Marshaler{}).Marshal(b, m); err != nil {
		t.Fatalf("jsonpb.Marshal() failed: %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, "https://example.org", b)
	if err != nil {
		t.Fatalf("http.NewRequest() failed: %v", err)
	}

	got := &dpb.Duration{}
	if err := DecodeProtoReq(got, req); err != nil {
		t.Fatalf("DecodeProtoReq() failed: %v", err)
	}
}

func Test_QueryParamWithDefault(t *testing.T) {
	uri := "https://example.org/index.html?user=alice"
	req, err := http.NewRequest(http.MethodGet, uri, nil)
	if err != nil {
		t.Fatalf("http.NewRequest() failed: %v", err)
	}

	got := QueryParamWithDefault(req, "user", "bob")
	want := "alice"
	if got != want {
		t.Fatalf("QueryParamWithDefault(%v, %v, %v) = %v, want %v", uri, "user", "bob", got, want)
	}
}

func Test_QueryParamWithDefault_Empty(t *testing.T) {
	uri := "https://example.org/index.html?user="
	req, err := http.NewRequest(http.MethodGet, uri, nil)
	if err != nil {
		t.Fatalf("http.NewRequest() failed: %v", err)
	}

	got := QueryParamWithDefault(req, "user", "bob")
	want := "bob"
	if got != want {
		t.Fatalf("QueryParamWithDefault(%v, %v, %v) = %v, want %v", uri, "user", "bob", got, want)
	}
}

func Test_QueryParamWithDefault_NotSet(t *testing.T) {
	uri := "https://example.org/index.html?account=foo"
	req, err := http.NewRequest(http.MethodGet, uri, nil)
	if err != nil {
		t.Fatalf("http.NewRequest() failed: %v", err)
	}

	got := QueryParamWithDefault(req, "user", "bob")
	want := "bob"
	if got != want {
		t.Fatalf("QueryParamWithDefault(%v, %v, %v) = %v, want %v", uri, "user", "bob", got, want)
	}
}

func Test_QueryParam(t *testing.T) {
	uri := "https://example.org/index.html?user=alice"
	req, err := http.NewRequest(http.MethodGet, uri, nil)
	if err != nil {
		t.Fatalf("http.NewRequest() failed: %v", err)
	}

	got := QueryParam(req, "user")
	want := "alice"
	if got != want {
		t.Fatalf("QueryParam(%v, %v) = %v, want %v", uri, "user", got, want)
	}
}

func Test_QueryParamInt(t *testing.T) {
	uri := "https://example.org/index.html?ts=60"
	req, err := http.NewRequest(http.MethodGet, uri, nil)
	if err != nil {
		t.Fatalf("http.NewRequest() failed: %v", err)
	}

	got := QueryParamInt(req, "ts")
	want := 60
	if got != want {
		t.Fatalf("QueryParamWithDefault(%v, %v) = %v, want %v", uri, "ts", got, want)
	}
}

func Test_QueryParamInt_Invalid(t *testing.T) {
	uri := "https://example.org/index.html?ts=string"
	req, err := http.NewRequest(http.MethodGet, uri, nil)
	if err != nil {
		t.Fatalf("http.NewRequest() failed: %v", err)
	}

	got := QueryParamInt(req, "ts")
	want := 0
	if got != want {
		t.Fatalf("QueryParamWithDefault(%v, %v) = %v, want %v", uri, "ts", got, want)
	}
}

func TestRequesterIP_FromHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	r.Header.Add("X-Forwarded-For", "192.168.1.2, 192.168.2.2")

	got := RequesterIP(r)
	want := "192.168.1.2"

	if got != want {
		t.Errorf("RequesterIP(r) = %s, %s", got, want)
	}
}

func TestRequesterIP_FromRemoteAddress(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	r.RemoteAddr = "192.168.1.2:12345"

	got := RequesterIP(r)
	want := "192.168.1.2"

	if got != want {
		t.Errorf("RequesterIP(r) = %s, %s", got, want)
	}
}

func TestTracingID(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	r.Header.Add("X-Cloud-Trace-Context", "1")

	got := TracingID(r)
	want := "1"

	if got != want {
		t.Errorf("TracingID(r) = %s, %s", got, want)
	}
}

func TestAbsolutePath(t *testing.T) {
	router := mux.NewRouter()
	absPath := ""
	want := "/path/{var}"
	router.HandleFunc(want, func(w http.ResponseWriter, r *http.Request) {
		absPath = AbsolutePath(r)
	})

	r := httptest.NewRequest(http.MethodGet, "https://example.com/path/a", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	if absPath != want {
		t.Errorf("absPath = %s wants %s", absPath, want)
	}
}
