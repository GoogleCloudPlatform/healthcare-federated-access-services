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

	"cloud.google.com/go/logging" /* copybara-comment: logging */
	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/globalflags" /* copybara-comment: globalflags */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/serviceinfo" /* copybara-comment: serviceinfo */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakesdl" /* copybara-comment: fakesdl */

	hrpb "google.golang.org/genproto/googleapis/logging/type" /* copybara-comment: http_request_go_proto */
	lspb "google.golang.org/genproto/googleapis/logging/type" /* copybara-comment: log_severity_go_proto */
	lepb "google.golang.org/genproto/googleapis/logging/v2" /* copybara-comment: log_entry_go_proto */
	lpb "google.golang.org/genproto/googleapis/logging/v2" /* copybara-comment: logging_go_proto */
)

func TestWriteAccessLog(t *testing.T) {
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
		TokenIssuer:     "http://issuer.example.com",
		TracingID:       "1",
		RequestMethod:   http.MethodGet,
		RequestEndpoint: "/path/of/endpoint",
		RequestIP:       "127.0.0.1",
		ErrorType:       "token_expired",
		PassAuthCheck:   false,
		ResponseCode:    http.StatusUnauthorized,
		Payload:         "This is message",
		Request:         req,
	}

	WriteAccessLog(context.Background(), server.Client, al)
	server.Client.Close()

	want := []*lpb.WriteLogEntriesRequest{{
		LogName: "projects/fake-project-id/logs/federated-access-audit",
		Entries: []*lepb.LogEntry{{
			Payload:  &lepb.LogEntry_TextPayload{TextPayload: al.Payload.(string)},
			Severity: lspb.LogSeverity_DEFAULT,
			Labels: map[string]string{
				"error_type":      al.ErrorType,
				"request_path":    al.RequestEndpoint,
				"token_id":        al.TokenID,
				"token_subject":   al.TokenSubject,
				"token_issuer":    al.TokenIssuer,
				"tracing_id":      "1",
				"type":            "access_log",
				"pass_auth_check": "false",
				"project_id":      "p1",
				"service_type":    "t1",
				"service_name":    "n1",
			},
			HttpRequest: &hrpb.HttpRequest{
				RequestUrl:    url,
				RequestMethod: req.Method,
				RemoteIp:      al.RequestIP,
				Status:        int32(al.ResponseCode),
			},
		}},
	}}

	got := server.Server.Logs

	got[0].Entries[0].Timestamp = nil
	got[0].Resource = nil
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Fatalf("Logs returned diff (-want +got):\n%s", diff)
	}
}

func TestWritePolicyDecisionLog(t *testing.T) {
	server, close := fakesdl.New()
	defer close()

	serviceinfo.Project = "p1"
	serviceinfo.Type = "t1"
	serviceinfo.Name = "n1"

	pl := &PolicyDecisionLog{
		TokenID:        "tid",
		TokenSubject:   "sub",
		TokenIssuer:    "http://issuer.example.com",
		Resource:       "http://example.com/dam/v1alpha/resources/a-dataset/roles/viewer",
		TTL:            "1d",
		PassAuthCheck:  false,
		ErrorType:      "untrusted_issuer",
		CartID:         "cart_id",
		ConfigRevision: 1,
		Message:        `{"error": "This is a json err"}`,
	}

	WritePolicyDecisionLog(server.Client, pl)
	server.Client.Close()

	want := []*lpb.WriteLogEntriesRequest{{
		LogName: "projects/fake-project-id/logs/federated-access-audit",
		Entries: []*lepb.LogEntry{{
			Severity: lspb.LogSeverity_DEFAULT,
			Payload:  &lepb.LogEntry_TextPayload{TextPayload: pl.Message.(string)},
			Labels: map[string]string{
				"type":            "policy_decision_log",
				"token_id":        "tid",
				"token_subject":   "sub",
				"token_issuer":    "http://issuer.example.com",
				"pass_auth_check": "false",
				"error_type":      "untrusted_issuer",
				"resource":        "http://example.com/dam/v1alpha/resources/a-dataset/roles/viewer",
				"ttl":             "1d",
				"project_id":      "p1",
				"service_type":    "t1",
				"service_name":    "n1",
				"cart_id":         "cart_id",
				"config_revision": "1",
			},
		}},
	}}

	got := server.Server.Logs

	got[0].Entries[0].Timestamp = nil
	got[0].Resource = nil
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Fatalf("Logs returned diff (-want +got):\n%s", diff)
	}
}

func TestWriteAccessLog_Disable_nil(t *testing.T) {
	writeLog(nil, logging.Entry{Payload: "this is a log"})

	// Do not crash.
}

func TestDisable_flag(t *testing.T) {
	globalflags.DisableAuditLog = true
	defer func() { globalflags.DisableAuditLog = false }()

	server, close := fakesdl.New()
	defer close()

	writeLog(server.Client, logging.Entry{Payload: "this is a log"})

	if len(server.Server.Logs) != 0 {
		t.Errorf("logs should not push to server")
	}
}
