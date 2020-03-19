// Copyright 2020 Google LLC
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

	"github.com/golang/protobuf/proto" /* copybara-comment */

	glog "github.com/golang/glog" /* copybara-comment */
	lepb "google.golang.org/genproto/googleapis/logging/v2" /* copybara-comment: log_entry_go_proto */
	lgrpcpb "google.golang.org/genproto/googleapis/logging/v2" /* copybara-comment: logging_go_grpc */
	lpb "google.golang.org/genproto/googleapis/logging/v2" /* copybara-comment: logging_go_proto */
)

// Server is a fake logging server.
type Server struct {
	// embed the GRPCLoggingServiceV2Server interface for non-implemented methods.
	lgrpcpb.LoggingServiceV2Server

	// Logs that have been sent to the server.
	Logs []*lpb.WriteLogEntriesRequest

	Enteries []*lepb.LogEntry
}

// WriteLogEntries stores the logs.
func (s *Server) WriteLogEntries(ctx context.Context, req *lpb.WriteLogEntriesRequest) (*lpb.WriteLogEntriesResponse, error) {
	glog.Infof("Logger.WriteLogEntries Request: %+v", req)
	s.Logs = append(s.Logs, proto.Clone(req).(*lpb.WriteLogEntriesRequest))
	s.Enteries = append(s.Enteries, req.GetEntries()...)
	return &lpb.WriteLogEntriesResponse{}, nil
}

func (s *Server) ListLogEntries(ctx context.Context, req *lpb.ListLogEntriesRequest) (*lpb.ListLogEntriesResponse, error) {
	glog.Infof("Logger.ListLogEntries Request: %+v", req)
	resp := &lpb.ListLogEntriesResponse{}
	for _, e := range s.Enteries {
		resp.Entries = append(resp.Entries, proto.Clone(e).(*lepb.LogEntry))
	}
	return resp, nil
}
