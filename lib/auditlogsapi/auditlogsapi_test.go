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

package auditlogsapi

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"cloud.google.com/go/logging" /* copybara-comment: logging */
	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"google.golang.org/api/option" /* copybara-comment: option */
	"google.golang.org/grpc" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/auditlog" /* copybara-comment: auditlog */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakegrpc" /* copybara-comment: fakegrpc */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakesdl" /* copybara-comment: fakesdl */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/timeutil" /* copybara-comment: timeutil */

	lgrpcpb "google.golang.org/genproto/googleapis/logging/v2" /* copybara-comment: logging_go_grpc */
	dpb "github.com/golang/protobuf/ptypes/duration" /* copybara-comment */
	apb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/auditlogs/v0" /* copybara-comment: auditlogs_go_proto */
)

func Test_AccessLog(t *testing.T) {
	ctx := context.Background()

	f, close := newFix(t)
	defer close()

	s := NewAuditLogs(f.logs)

	before := time.Now()
	auditlog.LogSync = true
	al := &auditlog.AccessLog{
		TokenID:         "tid",
		TokenSubject:    "sub",
		TokenIssuer:     "http://issuer.example.com",
		TracingID:       "1",
		RequestMethod:   http.MethodGet,
		RequestEndpoint: "/path/of/endpoint",
		RequestIP:       "127.0.0.1",
		ErrorType:       "token_expired",
		PassAuthCheck:   false,
		ResponseCode:    http.StatusUnauthorized,
		Payload:         "This is message",
		Request:         MustNewHTTPRequest(t, http.MethodGet, "http://example.com/path/of/endpoint", nil),
	}
	auditlog.WriteAccessLog(ctx, f.logger, al)
	pl := &auditlog.PolicyDecisionLog{
		TokenID:       "tid",
		TokenSubject:  "sub",
		TokenIssuer:   "http://issuer.example.com",
		Resource:      "http://example.com/dam/v1alpha/resources/a-dataset/roles/viewer",
		TTL:           "1d",
		PassAuthCheck: false,
		ErrorType:     "untrusted_issuer",
		Message:       `{"error": "This is a json err"}`,
	}
	auditlog.WritePolicyDecisionLog(f.logger, pl)
	after := time.Now()

	got, err := s.ListAuditLogs(ctx, &apb.ListAuditLogsRequest{Parent: "users/fake-user"})
	if err != nil {
		t.Fatalf("ListAuditLogs() failed: %v", err)
	}

	// Check time for logs and set to nil.
	var ts time.Time
	for _, l := range got.GetAuditLogs() {
		if al := l.GetAccessLog(); al != nil {
			ts = timeutil.Time(al.GetTime())
			if ts.Before(before) || ts.After(after) {
				t.Errorf("ListAuditLogs(): auditlog timestamp = %v, want in [%v,%v]", ts, before, after)
			}
			al.Time = nil
		}
		if pl := l.GetPolicyLog(); pl != nil {
			ts = timeutil.Time(pl.GetTime())
			if ts.Before(before) || ts.After(after) {
				t.Errorf("ListAuditLogs(): auditlog timestamp = %v, want in [%v,%v]", ts, before, after)
			}
			pl.Time = nil
		}
	}

	// TODO: use protocmp.IgnoreFields(&apb.AccessLog{}, "time") instead when it works.
	want := &apb.ListAuditLogsResponse{
		AuditLogs: []*apb.AuditLog{
			{
				Name: "users/todo-user-id/auditlogs/",
				AccessLog: &apb.AccessLog{
					ServiceName:      "unset-serviceinfo-Name",
					ServiceType:      "unset-serviceinfo-Type",
					TokenId:          "tid",
					TokenSubject:     "sub",
					TokenIssuer:      "http://issuer.example.com",
					Decision:         apb.Decision_FAIL,
					ErrorType:        "token_expired",
					Reason:           "This is message",
					MethodName:       "TODO",
					ResourceName:     "/path/of/endpoint",
					TracingId:        "1",
					CallerIp:         "TODO",
					HttpResponseCode: 0,
					HttpRequest:      nil,
				},
			},
			{
				Name: "users/todo-user-id/auditlogs/",
				PolicyLog: &apb.PolicyLog{
					ServiceName:  "unset-serviceinfo-Name",
					ServiceType:  "unset-serviceinfo-Type",
					TokenId:      "tid",
					TokenSubject: "sub",
					TokenIssuer:  "http://issuer.example.com",
					Decision:     apb.Decision_FAIL,
					ErrorType:    "untrusted_issuer",
					Reason:       `{"error": "This is a json err"}`,
					ResourceName: "http://example.com/dam/v1alpha/resources/a-dataset/roles/viewer",
					Ttl:          &dpb.Duration{Seconds: 86400},
				},
			},
		},
	}
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("ListAuditLogs() returned diff (-want +got):\n%s", diff)
	}
}

// Fix is a test fixture.
type Fix struct {
	rpc    *fakegrpc.Fake
	logSrv *fakesdl.Server
	logs   lgrpcpb.LoggingServiceV2Client
	logger *logging.Client
}

func newFix(t *testing.T) (*Fix, func() error) {
	t.Helper()
	ctx := context.Background()
	var cleanup func() error

	f := &Fix{}
	f.rpc, cleanup = fakegrpc.New()

	f.logSrv = &fakesdl.Server{}
	lgrpcpb.RegisterLoggingServiceV2Server(f.rpc.Server, f.logSrv)

	f.rpc.Start()

	opts := []option.ClientOption{
		option.WithGRPCConn(f.rpc.Client),
		option.WithoutAuthentication(),
		option.WithGRPCDialOption(grpc.WithInsecure()),
	}

	f.logs = lgrpcpb.NewLoggingServiceV2Client(f.rpc.Client)

	var err error
	f.logger, err = logging.NewClient(ctx, "projects/fake-project-id", opts...)
	if err != nil {
		t.Fatalf("logging.NewClient() failed: %v", err)
	}

	return f, cleanup
}

func MustNewHTTPRequest(t *testing.T, method string, url string, body io.Reader) *http.Request {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("http.NewRequest() failed: %v", err)
	}
	return req
}
