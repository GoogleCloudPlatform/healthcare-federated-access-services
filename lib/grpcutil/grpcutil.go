// Copyright 2020 Google LLC.
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

// Package grpcutil provides utilities to work with gRPC.
package grpcutil

import (
	"context"

	glog "github.com/golang/glog" /* copybara-comment */
	"google.golang.org/grpc/credentials" /* copybara-comment: credentials */
	"google.golang.org/grpc/credentials/oauth" /* copybara-comment: oauth */
	"google.golang.org/grpc" /* copybara-comment */
)

// NewGRPCClient creates a new GRPC client connect to the provided address.
func NewGRPCClient(ctx context.Context, addr string, opts ...grpc.DialOption) *grpc.ClientConn {
	opts = append(opts, grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, "")))
	creds, err := oauth.NewApplicationDefault(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		glog.Exitf("oauth.NewApplicationDefault() failed: %v", err)
	}
	opts = append(opts, grpc.WithPerRPCCredentials(creds))
	conn, err := grpc.Dial(addr, opts...)
	if err != nil {
		glog.Exitf("Failed to connect to %q: %v", addr, err)
	}
	return conn
}
