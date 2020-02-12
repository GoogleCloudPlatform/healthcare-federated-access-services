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
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
)

func TestWriteRedirect(t *testing.T) {
	w := NewFakeWriter()

	src := "https://fakeserver.org/srcresources/r1?param1=value1&param2=value2"
	r, err := http.NewRequest(http.MethodGet, src, nil)
	if err != nil {
		t.Fatalf("http.NewRequest(%v, %v, nil) failed: %v", http.MethodGet, src, err)
	}
	dst := "https://fakeserver.edu/dstresources/r2?param3=value3&param4=value4"

	WriteRedirect(w, r, dst)

	want := &FakeWriter{
		Headers: http.Header{
			"Access-Control-Allow-Headers": {"Content-Type, Origin, Accept, Authorization, X-Link-Authorization"},
			"Access-Control-Allow-Methods": {"GET,POST,PUT,PATCH,DELETE,OPTIONS"},
			"Access-Control-Allow-Origin":  {"*"},
			"Content-Type":                 {"text/html; charset=utf-8"},
			"Location":                     {dst},
		},
		Body: RedirectHTMLPage(dst),
		Code: http.StatusTemporaryRedirect,
	}
	if diff := cmp.Diff(w, want); diff != "" {
		t.Errorf("WriteRedirect(); Writer diff (-want +got):\n%s", diff)
	}
}

func TestWriteRedirect_ParsedDestination(t *testing.T) {
	w := NewFakeWriter()

	src := "https://fakeserver.org/srcresources/r1?param1=value1&param2=value2"
	r, err := http.NewRequest(http.MethodGet, src, nil)
	if err != nil {
		t.Fatalf("http.NewRequest(%v, %v, nil) failed: %v", http.MethodGet, src, err)
	}
	raw := "https://fakeserver.edu/dstresources/r2?param3=value3&param4=value4"
	addr, err := url.Parse(raw)
	if err != nil {
		t.Fatalf(" url.Parse(%v) failed: %v", addr, err)
	}
	dst := addr.String()

	WriteRedirect(w, r, dst)

	want := &FakeWriter{
		Headers: http.Header{
			"Access-Control-Allow-Headers": {"Content-Type, Origin, Accept, Authorization, X-Link-Authorization"},
			"Access-Control-Allow-Methods": {"GET,POST,PUT,PATCH,DELETE,OPTIONS"},
			"Access-Control-Allow-Origin":  {"*"},
			"Content-Type":                 {"text/html; charset=utf-8"},
			"Location":                     {raw},
		},
		Body: RedirectHTMLPage(dst),
		Code: http.StatusTemporaryRedirect,
	}
	if diff := cmp.Diff(w, want); diff != "" {
		t.Errorf("WriteRedirect(); Writer diff (-want +got):\n%s", diff)
	}
}

func TestWriteRedirect_RelativeDestination(t *testing.T) {
	w := NewFakeWriter()

	src := "https://fakeserver.org/srcresources/r1?param1=value1&param2=value2"
	r, err := http.NewRequest(http.MethodGet, src, nil)
	if err != nil {
		t.Fatalf("http.NewRequest(%v, %v, nil) failed: %v", http.MethodGet, src, err)
	}
	dst := "dstresources/r2?param3=value3&param4=value4"

	WriteRedirect(w, r, dst)

	want := &FakeWriter{
		Headers: http.Header{
			"Access-Control-Allow-Headers": {"Content-Type, Origin, Accept, Authorization, X-Link-Authorization"},
			"Access-Control-Allow-Methods": {"GET,POST,PUT,PATCH,DELETE,OPTIONS"},
			"Access-Control-Allow-Origin":  {"*"},
			"Content-Type":                 {"text/html; charset=utf-8"},
			"Location":                     {"/srcresources/" + dst},
		},
		Body: RedirectHTMLPage("/srcresources/" + dst),
		Code: http.StatusTemporaryRedirect,
	}
	if diff := cmp.Diff(w, want); diff != "" {
		t.Errorf("WriteRedirect(); Writer diff (-want +got):\n%s", diff)
	}
}

func TestWriteRedirect_RelativeDestinationAtRoot(t *testing.T) {
	w := NewFakeWriter()

	src := "https://fakeserver.org/srcresources/r1?param1=value1&param2=value2"
	r, err := http.NewRequest(http.MethodGet, src, nil)
	if err != nil {
		t.Fatalf("http.NewRequest(%v, %v, nil) failed: %v", http.MethodGet, src, err)
	}
	dst := "/dstresources/r2?param3=value3&param4=value4"

	WriteRedirect(w, r, dst)

	want := &FakeWriter{
		Headers: http.Header{
			"Access-Control-Allow-Headers": {"Content-Type, Origin, Accept, Authorization, X-Link-Authorization"},
			"Access-Control-Allow-Methods": {"GET,POST,PUT,PATCH,DELETE,OPTIONS"},
			"Access-Control-Allow-Origin":  {"*"},
			"Content-Type":                 {"text/html; charset=utf-8"},
			"Location":                     {dst},
		},
		Body: RedirectHTMLPage(dst),
		Code: http.StatusTemporaryRedirect,
	}
	if diff := cmp.Diff(w, want); diff != "" {
		t.Errorf("WriteRedirect(); Writer diff (-want +got):\n%s", diff)
	}
}

func TestWriteRedirect_FullyEncodedRedirectURLParameter(t *testing.T) {
	w := NewFakeWriter()

	dst := "https://fakeserver.edu/dstresources/r2?param3=value3&param4=value4"

	// Construct a request with a redirect_url parameter equal to encoded dst.
	p := "https://fakeserver.org/srcresources/r1"
	u, err := url.Parse(p)
	if err != nil {
		t.Fatalf("url.Parse(%v) failed: %v", p, err)
	}
	params := url.Values{}
	params.Add("param1", "value1")
	params.Add("param2", "value2")
	params.Add("redirect_url", dst)
	u.RawQuery = params.Encode()
	src := u.String()
	r, err := http.NewRequest(http.MethodGet, src, nil)
	if err != nil {
		t.Fatalf("http.NewRequest(%v, %v, nil) failed: %v", http.MethodGet, src, err)
	}
	if r.URL.String() != "https://fakeserver.org/srcresources/r1?param1=value1&param2=value2&redirect_url=https%3A%2F%2Ffakeserver.edu%2Fdstresources%2Fr2%3Fparam3%3Dvalue3%26param4%3Dvalue4" {
		t.Fatalf("test setup failed: request.URL is not correct: %q", r.URL.String())
	}
	redirect := r.URL.Query().Get("redirect_url")
	if redirect != dst {
		t.Fatalf("test setup failed: redirect_url is not correct: %q", redirect)
	}

	WriteRedirect(w, r, dst)

	want := &FakeWriter{
		Headers: http.Header{
			"Access-Control-Allow-Headers": {"Content-Type, Origin, Accept, Authorization, X-Link-Authorization"},
			"Access-Control-Allow-Methods": {"GET,POST,PUT,PATCH,DELETE,OPTIONS"},
			"Access-Control-Allow-Origin":  {"*"},
			"Content-Type":                 {"text/html; charset=utf-8"},
			"Location":                     {dst},
		},
		Body: RedirectHTMLPage(dst),
		Code: http.StatusTemporaryRedirect,
	}
	if diff := cmp.Diff(w, want); diff != "" {
		t.Errorf("WriteRedirect(); Writer diff (-want +got):\n%s", diff)
	}
}
