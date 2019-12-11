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

// Package testhttp contains helpers for test http request.
package testhttp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func request(t *testing.T, method, domainURL, path string, query url.Values, body io.Reader, header http.Header) *http.Request {
	t.Helper()

	u, err := url.Parse(domainURL + path)
	if err != nil {
		t.Fatalf("url.Parse(%s%s) failed %v", domainURL, path, err)
	}

	u.RawQuery = query.Encode()

	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		t.Fatalf("http.NewRequest(%s, %s, _) failed: %v", method, u.String(), err)
	}

	req.Header = header

	return req
}

// SendTestRequest sends request to handler.
func SendTestRequest(t *testing.T, handler http.Handler, method, path string, query url.Values, body io.Reader, header http.Header) *http.Response {
	t.Helper()

	s := httptest.NewServer(handler)
	defer s.Close()

	r := request(t, method, s.URL, path, query, body, header)

	resp, err := s.Client().Do(r)
	if err != nil {
		t.Fatalf("s.Client().Do(r) failed: %v", err)
	}

	return resp
}
