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
	"strconv"

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

	Entries []*lepb.LogEntry
}

// WriteLogEntries stores the logs.
func (s *Server) WriteLogEntries(ctx context.Context, req *lpb.WriteLogEntriesRequest) (*lpb.WriteLogEntriesResponse, error) {
	glog.Infof("Logger.WriteLogEntries Request: %+v", req)
	s.Logs = append(s.Logs, proto.Clone(req).(*lpb.WriteLogEntriesRequest))
	s.Entries = append(s.Entries, req.GetEntries()...)
	return &lpb.WriteLogEntriesResponse{}, nil
}

func (s *Server) ListLogEntries(ctx context.Context, req *lpb.ListLogEntriesRequest) (*lpb.ListLogEntriesResponse, error) {
	glog.Infof("Logger.ListLogEntries Request: %+v", req)
	resp := &lpb.ListLogEntriesResponse{}
	start := 0
	if next := req.PageToken; len(next) > 0 {
		start, _ = strconv.Atoi(next)
	}

	psize := int(req.GetPageSize())
	if psize == 0 {
		psize = 50
	}
	rows := len(s.Entries) - start

	for i := 0; i < rows; i++ {
		if i >= psize {
			resp.NextPageToken = strconv.Itoa(start + i)
			break
		}
		resp.Entries = append(resp.Entries, proto.Clone(s.Entries[start+i]).(*lepb.LogEntry))
	}
	return resp, nil
}
