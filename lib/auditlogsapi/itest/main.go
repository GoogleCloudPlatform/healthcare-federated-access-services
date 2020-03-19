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

// Binary itest is an integration test for the API with the Stackdriver.
package main

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"time"

	glog "github.com/golang/glog" /* copybara-comment */
	"cloud.google.com/go/logging" /* copybara-comment: logging */
	"google.golang.org/api/option" /* copybara-comment: option */
	"google.golang.org/grpc/credentials" /* copybara-comment: credentials */
	"google.golang.org/grpc/credentials/oauth" /* copybara-comment: oauth */
	"google.golang.org/grpc" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/auditlog" /* copybara-comment: auditlog */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/auditlogsapi" /* copybara-comment: auditlogsapi */

	lgrpcpb "google.golang.org/genproto/googleapis/logging/v2" /* copybara-comment: logging_go_grpc */
	lpb "google.golang.org/genproto/googleapis/logging/v2" /* copybara-comment: logging_go_proto */
	apb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/auditlogs/v0" /* copybara-comment: auditlogs_go_proto */
)

var (
	projectID = flag.String("project_id", "", "GCP project ID")
	sdlAddr   = flag.String("sdl_addr", "logging.googleapis.com:443", "The address for Stackdriver Logging API")
)

func main() {
	ctx := context.Background()
	flag.Parse()
	conn := NewGRPCClient(ctx, *sdlAddr)
	defer conn.Close()

	projectName := "projects/" + *projectID

	sdlc := lgrpcpb.NewLoggingServiceV2Client(conn)
	logger := NewLogger(ctx, conn, projectName)

	s := auditlogsapi.NewAuditLogs(sdlc)

	TestToAuditLog(ctx, sdlc, projectName)
	TestListAuditLog(ctx, s, sdlc, logger, projectName)

	glog.Exit()
}

// TestToAuditLog reads logs audit logs from Stackdriver Logging and displays them.
// Checks that the way we call the Stackdriver Logging actually works and can convert the format.
func TestToAuditLog(ctx context.Context, c lgrpcpb.LoggingServiceV2Client, projectName string) {
	glog.Infof("TestToAuditLog started.")
	defer glog.Infof("TestToAuditLog finished.")

	since := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
	filters := []string{
		fmt.Sprintf("timestamp>=%q", since.Format(time.RFC3339)),
		`logName="` + projectName + `/logs/federated-access-audit"`,
	}
	req := &lpb.ListLogEntriesRequest{
		ResourceNames: []string{projectName},
		PageSize:      1000,
		OrderBy:       "timestamp desc",
		Filter:        strings.Join(filters, " AND "),
	}
	glog.Infof("Request: %v\n\n", req)

	resp, err := c.ListLogEntries(ctx, req)
	if err != nil {
		glog.Exitf("ListLogEntries() failed: %v", err)
	}

	for _, e := range resp.GetEntries() {
		l, _ := auditlogsapi.ToAuditLog(e)
		glog.Infof("AuditLog: %v\n\n", l)
	}
}

// TestListAuditLog checks the intergration of both auditlog and auditlogsapi packages with Stackdriver logging.
func TestListAuditLog(ctx context.Context, s *auditlogsapi.AuditLogs, c lgrpcpb.LoggingServiceV2Client, logger *logging.Client, projectName string) {
	glog.Infof("TestListAuditLog started.")
	defer glog.Infof("TestListAuditLog finished.")

	resp, err := s.ListAuditLogs(ctx, &apb.ListAuditLogsRequest{Parent: "users/fake-user-id"})
	if err != nil {
		glog.Exitf("ListAuditLogs() failed: %v", err)
	}

	for _, l := range resp.GetAuditLogs() {
		glog.Infof("AuditLog: %v\n\n", l)
	}
}

// NewGRPCClient creates a new GRPC client connect to the provided address.
func NewGRPCClient(ctx context.Context, addr string, opts ...grpc.DialOption) *grpc.ClientConn {
	opts = append(opts, grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(nil, "")))
	creds, err := oauth.NewApplicationDefault(ctx)
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

// NewLogger creates a new logger.
func NewLogger(ctx context.Context, conn *grpc.ClientConn, projectName string) *logging.Client {
	auditlog.LogSync = true
	logger, err := logging.NewClient(ctx, projectName, option.WithGRPCConn(conn))
	if err != nil {
		glog.Exitf("logging.NewClient(ctx,%v) failed: %v", projectName, err)
	}
	return logger
}
