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
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux" /* copybara-comment */
	"github.com/golang/protobuf/jsonpb" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */

	glog "github.com/golang/glog" /* copybara-comment */
)

// This file contains the utilities for working with http.Request.

// DecodeProto decodes a reader with JSON coded protobuffer message content.
func DecodeProto(m proto.Message, b io.Reader) error {
	if err := jsonpb.Unmarshal(b, m); err != nil && err != io.EOF {
		return err
	}
	return nil
}

// DecodeProtoReq decodes a request with protobuffer message body.
func DecodeProtoReq(m proto.Message, req *http.Request) error {
	return DecodeProto(m, req.Body)
}

// EncodeProto decodes a reader with JSON coded protobuffer message content.
func EncodeProto(m proto.Message) (io.Reader, error) {
	b := bytes.NewBuffer(nil)
	if err := (&jsonpb.Marshaler{}).Marshal(b, m); err != nil {
		return nil, err
	}
	return b, nil
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

// RequesterIP find the requester ip from http request.
func RequesterIP(r *http.Request) string {
	if ip := fromXForwardForHeader(r); len(ip) != 0 {
		return ip
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		glog.Warningf("r.RemoteAddr: %q is not IP:port", r.RemoteAddr)
		return ""
	}
	return ip
}

// fromXForwardForHeader find the ip from X-Forwarded-For header
// See https://cloud.google.com/appengine/docs/flexible/python/reference/request-headers#app_engine-specific_headers
// This method also works for any proxy use X-Forwarded-For to pass the client ip.
func fromXForwardForHeader(r *http.Request) string {
	h := r.Header.Get("X-Forwarded-For")
	s := strings.Split(h, ",")
	if len(s) == 0 {
		return ""
	}

	return strings.TrimSpace(s[0])
}

// TracingID find the tracing id in the request
// See https://cloud.google.com/appengine/docs/flexible/python/reference/request-headers#app_engine-specific_headers
func TracingID(r *http.Request) string {
	return r.Header.Get("X-Cloud-Trace-Context")
}

// AbsolutePath find the registered path in the mux router.
// eg. register "/path/{var}" in router, request to "/path/a"
// AbsolutePath(r) will return "/path/{var}".
func AbsolutePath(r *http.Request) string {
	s, err := mux.CurrentRoute(r).GetPathTemplate()
	if err != nil {
		return r.URL.Path
	}

	return s
}
