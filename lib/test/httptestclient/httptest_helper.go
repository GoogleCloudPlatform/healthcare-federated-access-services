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

// Package httptestclient contains a http client request to the given http handler.
package httptestclient

import (
	"net/http"
	"net/http/httptest"
)

type stubRoundTripper struct {
	handler http.Handler
}

// RoundTrip executes provided Request in the handler of stubRoundTripper.
func (s *stubRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	s.handler.ServeHTTP(w, r)
	return w.Result(), nil
}

// New returns a http client request to the given http handler.
func New(handler http.Handler) *http.Client {
	return &http.Client{Transport: &stubRoundTripper{handler: handler}}
}
