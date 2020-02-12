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

// Package fakegrpc provides a fake gRPC client/server for testing purpose.
package fakegrpc

import (
	"net"

	glog "github.com/golang/glog" /* copybara-comment */
	"google.golang.org/grpc" /* copybara-comment */
)

// Fake contains the server and client for a GRPC connection.
type Fake struct {
	Listener net.Listener
	Server   *grpc.Server
	Client   *grpc.ClientConn
}

// New creates a gRPC client and server connected to eachother.
func New() (*Fake, func() error) {
	f := &Fake{}

	// Create a gRPC server.
	f.Server = grpc.NewServer()

	// ":0" means pick a random free port on the local host.
	port := ":0"

	// Listen on the given TCP port.
	var err error
	f.Listener, err = net.Listen("tcp", port)
	if err != nil {
		glog.Fatalf("net.Listen(\"tcp\", %v) failed: %v", port, err)
	}

	// Set up a client connection to the server.
	addr := f.Listener.Addr().String()
	f.Client, err = grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		glog.Fatalf("grpc.Dial(%v, _) failed: %v", addr, err)
	}

	return f, f.Client.Close
}

// Start starts the server.
// Must be called after registering the services on the server.
func (f *Fake) Start() func() error {
	// gRPC server serves on the port.
	go func() {
		if err := f.Server.Serve(f.Listener); err != nil {
			glog.Fatalf("server.Serve(_) failed: %v", err)
		}
	}()

	return func() error {
		f.Server.Stop()
		return nil
	}
}
