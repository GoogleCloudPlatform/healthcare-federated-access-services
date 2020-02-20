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

// Package server provides a http server with request timeout and grateful shutdown.
package server

import (
	"context"
	"net/http"
	"time"

	glog "github.com/golang/glog" /* copybara-comment */
)

// Server contains a http server.
type Server struct {
	name string
	port string
	srv  *http.Server
}

// New returns a server, and start it.
func New(name, port string, handler http.Handler) *Server {
	srv := &http.Server{
		Addr: ":" + port,
		// Good practice to set timeouts to avoid Slowloris attacks.
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      handler,
	}

	return &Server{
		name: name,
		port: port,
		srv:  srv,
	}
}

// ServeUnblock serves the http server inside a goroutine so that it doesn't block.
// Will crash if the server failed to bind the port.
func (s *Server) ServeUnblock() {
	glog.Infof("%s listening on port %v", s.name, s.port)
	go func() {
		if err := s.srv.ListenAndServe(); err != http.ErrServerClosed {
			glog.Fatalf("%s listening on %v failed: %v", s.name, s.port, err)
		}
	}()
}

// Shutdown the server, doesn't block if no connections, but will otherwise wait
// until the timeout deadline.
func (s *Server) Shutdown() {
	// Create a deadline to wait for.
	wait := time.Second * 15
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()

	s.srv.Shutdown(ctx)
	glog.Infof("%s shutting down", s.name)
}
