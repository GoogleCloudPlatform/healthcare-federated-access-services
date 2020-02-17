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
	"bytes"
	"net/http"
	"testing"

	dpb "github.com/golang/protobuf/ptypes/duration" /* copybara-comment */
	"github.com/golang/protobuf/jsonpb" /* copybara-comment */
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
