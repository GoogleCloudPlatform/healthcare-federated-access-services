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
)

// FakeWriter is a fake HTTP response writer.
// See http.ResponseWriter.
type FakeWriter struct {
	Headers http.Header
	Body    string
	Code    int
}

// NewFakeWriter creates a new FakeWriter.
func NewFakeWriter() *FakeWriter {
	return &FakeWriter{Headers: make(http.Header)}
}

// Header returns the header.
func (w *FakeWriter) Header() http.Header {
	return w.Headers
}

// Write appends to the Body.
func (w *FakeWriter) Write(b []byte) (int, error) {
	w.Body = w.Body + string(b)
	return len(b), nil
}

// WriteHeader writes the HTTP status code.
func (w *FakeWriter) WriteHeader(code int) {
	w.Code = code
}
