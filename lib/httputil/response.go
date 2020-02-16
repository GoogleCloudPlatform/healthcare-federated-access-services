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

// This file contains the utilities for working with http.Response.

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"testing"
)

// EncodeJSON encodes an object into JSON and writes it to io.Writer.
func EncodeJSON(w io.Writer, v interface{}) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("json.Marshal(%+v) failed: %v", v, err)
	}
	if _, err := w.Write(b); err != nil {
		return fmt.Errorf("io.Writer.Write failed: %v", err)
	}
	return nil
}

// DecodeJSON reads JSON from io.Reader and decodes it into an object.
func DecodeJSON(r io.Reader, v interface{}) error {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return fmt.Errorf("ioutil.ReadAll failed: %v", err)
	}
	err = json.Unmarshal(b, v)
	if err != nil {
		return fmt.Errorf("json.Unmarshal(%s) failed: %v", string(b), err)
	}
	return nil
}

// MustDecodeRPCResp is the test helper for DecodeRPCResp.
// TODO: move to a test package.
func MustDecodeRPCResp(t *testing.T, resp *http.Response, v interface{}) {
	t.Helper()
	if err := DecodeJSON(resp.Body, v); err != nil {
		t.Fatalf("httputil.DecodeRPCResp(%v, %T) failed: %v", resp, v, err)
	}
}
