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

package fakehttp

import (
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
)

type Resp struct {
	Result string `json:"result"`
}

func TestNew(t *testing.T) {
	f, cleanup := New()
	defer cleanup()

	req, err := http.NewRequest("GET", f.Server.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest(%v,%v) failed: %v", "GET", f.Server.URL, err)
	}

	resp, err := f.Client.Do(req)
	if err != nil {
		t.Fatalf("Client.Do(%+v) failed: %v", req, err)
	}
	got := &Resp{}
	if err := DecodeResponse(resp, got); err != nil {
		t.Fatalf("DecodeResponse(%v,%T) failed: %v", resp, got, err)
	}

	want := &Resp{}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Client.Do(%+v).Response.Body returned diff:%s\n", req, diff)
	}
}

func TestNew_Error(t *testing.T) {
	f, cleanup := New()
	defer cleanup()

	f.Handler = func(req *http.Request) (interface{}, error) {
		return nil, status.Errorf(codes.NotFound, "")
	}
	req, err := http.NewRequest("GET", f.Server.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest(%v,%v) failed: %v", "GET", f.Server.URL, err)
	}

	resp, err := f.Client.Do(req)
	if err != nil {
		t.Errorf("Client.Do(%+v) failed: %v", req, err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Client.Do(%+v).Response.StatusCode = %v, want %v", req, resp.StatusCode, http.StatusNotFound)
	}
}

func TestNew_PrefixHandlers(t *testing.T) {
	f, cleanup := New()
	defer cleanup()

	f.Handler = PrefixHandlers{
		"/prefix0": func(req *http.Request) (interface{}, error) { return &Resp{Result: "0"}, nil },
		"/prefix1": func(req *http.Request) (interface{}, error) { return &Resp{Result: "1"}, nil },
	}.Handler

	req, err := http.NewRequest("GET", f.Server.URL+"/prefix1", nil)
	if err != nil {
		t.Fatalf("NewRequest(%v,%v) failed: %v", "GET", f.Server.URL, err)
	}

	resp, err := f.Client.Do(req)
	if err != nil {
		t.Fatalf("Client.Do(%+v) failed: %v", req, err)
	}
	got := &Resp{}
	if err := DecodeResponse(resp, got); err != nil {
		t.Fatalf("DecodeResponse(%v,%T) failed: %v", resp, got, err)
	}

	want := &Resp{Result: "1"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Client.Do(%+v).Response.Body returned diff:%s\n", req, diff)
	}

}
