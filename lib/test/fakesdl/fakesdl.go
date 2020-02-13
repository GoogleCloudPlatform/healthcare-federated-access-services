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

// Package fakesdl provides a fake for Stackdriver Logging.
package fakesdl

import (
	"context"

	glog "github.com/golang/glog" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
	"cloud.google.com/go/logging" /* copybara-comment: logging */
	"google.golang.org/api/option" /* copybara-comment: option */
	"google.golang.org/grpc" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakegrpc" /* copybara-comment: fakegrpc */

	lgrpcpb "google.golang.org/genproto/googleapis/logging/v2" /* copybara-comment: logging_go_grpc */
	lpb "google.golang.org/genproto/googleapis/logging/v2" /* copybara-comment: logging_go_proto */
)

// Fake contains a server and client.
type Fake struct {
	GRPC   *fakegrpc.Fake
	Server *Server
	Client *logging.Client
}

// New creates a new Fake.
func New() (*Fake, func()) {
	ctx := context.Background()

	rpc, cleanup := fakegrpc.New()

	s := &Server{}
	lgrpcpb.RegisterLoggingServiceV2Server(rpc.Server, s)

	stop := rpc.Start()

	c, err := logging.NewClient(ctx, "projects/fake-project-id", option.WithGRPCConn(rpc.Client), option.WithoutAuthentication(), option.WithGRPCDialOption(grpc.WithInsecure()))
	if err != nil {
		glog.Fatalf("Creating Stackdriver Logging client failed: %v", err)
	}

	return &Fake{
			GRPC:   rpc,
			Server: s,
			Client: c,
		}, func() {
			cleanup()
			stop()
		}
}

// Server is a fake logging server.
type Server struct {
	// embed the GRPCLoggingServiceV2Server interface for non-implemented methods.
	lgrpcpb.LoggingServiceV2Server

	// Logs that have been sent to the server.
	Logs []*lpb.WriteLogEntriesRequest
}

// WriteLogEntries stores the logs.
func (l *Server) WriteLogEntries(ctx context.Context, req *lpb.WriteLogEntriesRequest) (*lpb.WriteLogEntriesResponse, error) {
	glog.Infof("Logger.WriteLogEntries Request: %+v", req)
	l.Logs = append(l.Logs, proto.Clone(req).(*lpb.WriteLogEntriesRequest))
	return &lpb.WriteLogEntriesResponse{}, nil
}
