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
// To run the test:
//   go run lib/auditlogsapi/itest/main.go --alsologtostderr --project=ghasemloo-hcls-fa8 --user="subject"
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"strings"
	"time"

	glog "github.com/golang/glog" /* copybara-comment */
	"cloud.google.com/go/logging" /* copybara-comment: logging */
	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"google.golang.org/api/option" /* copybara-comment: option */
	"google.golang.org/grpc" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */
	"github.com/pborman/uuid" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/auditlog" /* copybara-comment: auditlog */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/auditlogsapi" /* copybara-comment: auditlogsapi */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/grpcutil" /* copybara-comment: grpcutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */

	lgrpcpb "google.golang.org/genproto/googleapis/logging/v2" /* copybara-comment: logging_go_grpc */
	lpb "google.golang.org/genproto/googleapis/logging/v2" /* copybara-comment: logging_go_proto */
	dpb "github.com/golang/protobuf/ptypes/duration" /* copybara-comment */
	apb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/auditlogs/v0" /* copybara-comment: auditlogs_go_proto */
)

var (
	projectID = flag.String("project", "", "GCP project ID")
	userID    = flag.String("user", "", "user id (cirrently the subject of tokens)")
	sdlAddr   = flag.String("sdl_addr", "logging.googleapis.com:443", "The address for Stackdriver Logging API")
)

func main() {
	ctx := context.Background()
	flag.Parse()
	conn := grpcutil.NewGRPCClient(ctx, *sdlAddr)
	defer conn.Close()

	projectName := "projects/" + *projectID

	sdlc := lgrpcpb.NewLoggingServiceV2Client(conn)
	logger := NewLogger(ctx, conn, *projectID)

	s := auditlogsapi.NewAuditLogs(sdlc, *projectID)

	TestListLogEntriesRequest(ctx, sdlc, projectName, *userID)
	TestListAuditLogFromProject(ctx, s, projectName, *userID)
	TestAuditLog(ctx, s, sdlc, logger, projectName, *userID)

	glog.Exit()
}

// TestListLogEntriesRequest reads logs audit logs from Stackdriver Logging and displays them.
// Checks that the way we call the Stackdriver Logging actually works.
func TestListLogEntriesRequest(ctx context.Context, c lgrpcpb.LoggingServiceV2Client, projectName string, userID string) {
	glog.Infof("## TestListLogEntriesRequest started. ##")
	defer glog.Infof("## TestListLogEntriesRequest finished. ##\n\n")

	since := time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC)
	filters := []string{
		fmt.Sprintf("timestamp>=%q", since.Format(time.RFC3339)),
		`logName="` + projectName + `/logs/federated-access-audit"`,
		`labels.token_subject="` + userID + `"`,
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
		glog.Errorf("ListLogEntries() failed: %v", err)
		return
	}
	glog.Infof("Response: %v\n\n", resp)
}

// TestListAuditLogFromProject checks the intergration of both auditlogsapi packages with Stackdriver logging.
// Gets auditlogs for the specified user with default options for listing and logs them.
func TestListAuditLogFromProject(ctx context.Context, s *auditlogsapi.AuditLogs, projectName string, userID string) {
	glog.Infof("## TestListAuditLogFromProject started. ##")
	defer glog.Infof("## TestListAuditLogFromProject finished. ##\n\n")
	resp, err := s.ListAuditLogs(ctx, &apb.ListAuditLogsRequest{Parent: "users/" + userID})
	if err != nil {
		glog.Errorf("ListAuditLogs() failed: %v", err)
		return
	}
	for _, l := range resp.GetAuditLogs() {
		glog.Infof("AuditLog: %v\n\n", l)
	}
}

// TestAuditLog checks the intergration of both auditlog and auditlogsapi packages with Stackdriver logging.
// It creates audit logs for a user (a generated uuid) and lists and logs them.
func TestAuditLog(ctx context.Context, s *auditlogsapi.AuditLogs, c lgrpcpb.LoggingServiceV2Client, logger *logging.Client, projectName string, userID string) {
	glog.Infof("## TestAuditLog started. ##")
	defer glog.Infof("## TestAuditLog finished. ##\n\n")

	// Generate random user id if no user is specified.
	randomUser := false
	if userID == "" {
		userID = "fake-user-id-" + uuid.New()
		randomUser = true
	}

	// Write an access and a policy log.
	al := &auditlog.AccessLog{
		TokenID:         "fake-token-id",
		TokenSubject:    userID,
		TokenIssuer:     "fake-issuer-id",
		TracingID:       "fake-tracing-id",
		RequestMethod:   "fake-method",
		RequestEndpoint: "fake-endpoint",
		RequestIP:       "fake-requester-ip",
		ErrorType:       "fake-error-type",
		ResponseCode:    1234,
		Request:         httputils.MustNewReq(http.MethodGet, "http://fake.org/fake-path", nil),
		PassAuthCheck:   true,
		Payload:         "fake-reason",
	}
	auditlog.WriteAccessLog(ctx, logger, al)

	pl := &auditlog.PolicyDecisionLog{
		TokenID:       "fake-token-id",
		TokenSubject:  userID,
		TokenIssuer:   "fake-issuer-id",
		Resource:      "fake-resource",
		TTL:           time.Hour.String(),
		PassAuthCheck: true,
		ErrorType:     "fake-error-type",
		Message:       "fake-reason",
	}
	auditlog.WritePolicyDecisionLog(logger, pl)

	// It takes a while before written logs are visible on Stackdriver.
	var got *apb.ListAuditLogsResponse
	end := time.Now().Add(time.Minute)
	for len(got.GetAuditLogs()) < 2 && time.Now().Before(end) {
		var err error
		got, err = s.ListAuditLogs(ctx, &apb.ListAuditLogsRequest{Parent: "users/" + userID})
		if err != nil {
			glog.Errorf("ListAuditLogs() failed: %v", err)
			return
		}
		time.Sleep(time.Second)
	}

	for _, l := range got.GetAuditLogs() {
		glog.Infof("AuditLog: %v\n\n", l)
	}

	if !randomUser {
		return
	}
	// If it was a randomly generated user, we can check if the logs are correct.

	if got.AuditLogs[0].AccessLog == nil {
		got.AuditLogs[0], got.AuditLogs[1] = got.AuditLogs[1], got.AuditLogs[0]
	}
	got.AuditLogs[0].Name = ""
	got.AuditLogs[0].AccessLog.Time = nil
	got.AuditLogs[1].Name = ""
	got.AuditLogs[1].PolicyLog.Time = nil

	want := &apb.ListAuditLogsResponse{
		AuditLogs: []*apb.AuditLog{
			{
				Name: "",
				AccessLog: &apb.AccessLog{
					ServiceName:      "unset-serviceinfo-Name",
					ServiceType:      "unset-serviceinfo-Type",
					TokenId:          "fake-token-id",
					TokenSubject:     userID,
					TokenIssuer:      "fake-issuer-id",
					Decision:         apb.Decision_PASS,
					ErrorType:        "fake-error-type",
					Reason:           "fake-reason",
					MethodName:       http.MethodGet,
					ResourceName:     "fake-endpoint",
					TracingId:        "fake-tracing-id",
					CallerIp:         "fake-requester-ip",
					HttpResponseCode: 1234,
					HttpRequest:      nil,
				},
			},
			{
				Name: "",
				PolicyLog: &apb.PolicyLog{
					ServiceName:  "unset-serviceinfo-Name",
					ServiceType:  "unset-serviceinfo-Type",
					TokenId:      "fake-token-id",
					TokenSubject: userID,
					TokenIssuer:  "fake-issuer-id",
					Decision:     apb.Decision_PASS,
					ErrorType:    "fake-error-type",
					Reason:       "fake-reason",
					ResourceName: "fake-resource",
					Ttl:          &dpb.Duration{Seconds: int64(time.Hour / time.Second)},
				},
			},
		},
	}
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		glog.Errorf("ListAuditLogs() returned diff (-want +got):\n%s", diff)
	}
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
