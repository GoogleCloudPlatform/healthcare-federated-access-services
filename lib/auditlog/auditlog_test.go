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

package auditlog

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/serviceinfo" /* copybara-comment: serviceinfo */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakesdl" /* copybara-comment: fakesdl */

	mrpb "google.golang.org/genproto/googleapis/api/monitoredres" /* copybara-comment */
	hrpb "google.golang.org/genproto/googleapis/logging/type" /* copybara-comment: http_request_go_proto */
	lspb "google.golang.org/genproto/googleapis/logging/type" /* copybara-comment: log_severity_go_proto */
	lepb "google.golang.org/genproto/googleapis/logging/v2" /* copybara-comment: log_entry_go_proto */
	lpb "google.golang.org/genproto/googleapis/logging/v2" /* copybara-comment: logging_go_proto */
)

func TestLoggingAccessLog(t *testing.T) {
	server, close := fakesdl.New()
	defer close()

	serviceinfo.Project = "p1"
	serviceinfo.Type = "t1"
	serviceinfo.Name = "n1"

	url := "http://example.com/path/of/endpoint"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("http.NewRequest() failed: %v", err)
	}

	al := &AccessLog{
		TokenID:         "tid",
		TokenSubject:    "sub",
		RequestMethod:   http.MethodGet,
		RequestEndpoint: "/path/of/endpoint",
		RequestIP:       "127.0.0.1",
		ErrorType:       "token_expired",
		ResponseCode:    http.StatusUnauthorized,
		Payload:         "This is message",
		Request:         req,
	}

	WriteAccessLog(context.Background(), server.Client, al)
	server.Client.Close()

	want := []*lpb.WriteLogEntriesRequest{{
		LogName: "projects/fake-project-id/logs/federated-access-audit",
		Resource: &mrpb.MonitoredResource{
			Type: "project",
			Labels: map[string]string{
				"project_id": "fake-project-id",
			},
		},
		Entries: []*lepb.LogEntry{{
			Payload:  &lepb.LogEntry_TextPayload{TextPayload: al.Payload.(string)},
			Severity: lspb.LogSeverity_DEFAULT,
			Labels: map[string]string{
				"error_type":    al.ErrorType,
				"request_path":  al.RequestEndpoint,
				"token_id":      al.TokenID,
				"token_subject": al.TokenSubject,
				"type":          "access_log",
			},
			HttpRequest: &hrpb.HttpRequest{
				RequestUrl:    url,
				RequestMethod: req.Method,
				RemoteIp:      al.RequestIP,
				Status:        int32(al.ResponseCode),
			},
			Resource: &mrpb.MonitoredResource{
				Type: "github.com/GoogleCloudPlatform/healthcare-federated-access-services",
				Labels: map[string]string{
					"project_id":   "p1",
					"service_type": "t1",
					"service_name": "n1",
				},
			},
		}},
	}}

	got := server.Server.Logs

	if diff := cmp.Diff(want, got, protocmp.Transform(), protocmp.IgnoreFields(&lepb.LogEntry{}, "timestamp")); diff != "" {
		t.Fatalf("Logs returned diff (-want +got):\n%s", diff)
	}
}
