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

// Package fakehttp provides a fake HTTP server for tests that have dependencies using HTTP clients.
package fakehttp

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"

	glog "github.com/golang/glog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common"
)

// Handler handles HTTP requests.
type Handler func(req *http.Request) (body interface{}, err error)

// DefaultHandler is a default HTTP request handler that returns a nil body.
func DefaultHandler(req *http.Request) (interface{}, error) {
	return nil, nil
}

// HTTP provides an HTTP server routing calls to its handler and a client connected to it.
type HTTP struct {
	// Handler is handler for HTTP requests.
	Handler Handler
	// Server is the HTTP server. Uses handler for handling requests.
	Server *httptest.Server
	// Client is the HTTP client connected to the HTTP server.
	Client *http.Client
}

// New creates a new HTTP server and client.
func New() (*HTTP, func() error) {
	f := &HTTP{}
	f.Handler = DefaultHandler
	h := func(w http.ResponseWriter, req *http.Request) {
		glog.Infof("HTTP Request: %+v", req)
		defer glog.Infof("HTTP Response: %+v", req.Response)

		body, err := f.Handler(req)
		if err != nil {
			code := common.FromError(err)
			http.Error(w, err.Error(), code)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(body); err != nil {
			glog.Errorf("json.NewEncoder(%v).Encode(%v) failed: %v", w, body, err)
			http.Error(w, "encoding the response failed", http.StatusInternalServerError)
			return
		}
	}

	f.Server = httptest.NewServer(http.HandlerFunc(h))
	f.Client = f.Server.Client()
	cleanup := func() error {
		f.Server.Close()
		return nil
	}
	return f, cleanup
}

// PrefixHandlers demuxes calls based on URL path prefix.
// The first handler whose prefix matches will be called.
type PrefixHandlers map[string]Handler

// Handler handles HTTP requests.
func (p PrefixHandlers) Handler(req *http.Request) (body interface{}, err error) {
	path := req.URL.Path
	for prefix, h := range p {
		if strings.HasPrefix(path, prefix) {
			return h(req)
		}
	}
	return nil, status.Errorf(codes.NotFound, "no handler found for %q", path)
}

// DecodeResponse decodes the HTTP Response.Body JSON.
func DecodeResponse(resp *http.Response, v interface{}) error {
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("ioutil.ReadAll(_) failed: %v", err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("json.Unmarshal(%q,%T) failed: %v", b, v, err)
	}
	return nil
}
