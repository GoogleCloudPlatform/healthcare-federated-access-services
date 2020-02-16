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
	"io"
	"net/http"
	"strconv"

	"github.com/golang/protobuf/jsonpb" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
)

// This file contains the utilities for working with http.Request.

// DecodeProtoReq decodes a request with protobuffer message body.
func DecodeProtoReq(m proto.Message, req *http.Request) error {
	if err := jsonpb.Unmarshal(req.Body, m); err != nil && err != io.EOF {
		return err
	}
	return nil
}

// QueryParamWithDefault returns a URL query parameter value.
// If not set or empty, the provided default value is returned.
func QueryParamWithDefault(r *http.Request, name string, d string) string {
	if v := r.FormValue(name); len(v) > 0 {
		return v
	}
	return d
}

// QueryParam returns a URL query parameter value.
func QueryParam(r *http.Request, name string) string {
	return QueryParamWithDefault(r, name, "")
}

// QueryParamInt  returns a URL query parameter value of int type.
// Returns 0 if missing or invalid.
func QueryParamInt(r *http.Request, name string) int {
	v, err := strconv.Atoi(QueryParam(r, name))
	if err != nil {
		return 0
	}
	return v
}
