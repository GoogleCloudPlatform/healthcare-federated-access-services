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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */

	apb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/auditlogs/v0" /* copybara-comment: auditlogs_go_proto */
)

func TestListAuditLogs(t *testing.T) {
	ts := NewAuditLogsHandler(&Stub{})
	s := httptest.NewServer(http.HandlerFunc(ts.ListAuditLogs))
	defer s.Close()

	name := "/users/fake-user/logs"
	resp, err := s.Client().Get(s.URL + name)
	if err != nil {
		t.Fatalf("ListAuditLogs failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ListAuditLogs failed: %v", resp.Status)
	}

	got := &apb.ListAuditLogsResponse{}
	httputils.MustDecodeJSONPBResp(t, resp, got)

	want := &apb.ListAuditLogsResponse{AuditLogs: []*apb.AuditLog{FakeAuditLog}}
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("ListAuditLogs(%s) returned diff (-want +got):\n%s", name, diff)
	}
}
