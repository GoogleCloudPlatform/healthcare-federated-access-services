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
	"strings"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */

	agpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/auditlogs/v0" /* copybara-comment: auditlogs_go_grpc_proto */
	apb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/auditlogs/v0" /* copybara-comment: auditlogs_go_proto */
)

// AuditLogsHandler is a HTTP handler wrapping a GRPC server.
type AuditLogsHandler struct {
	s agpb.AuditLogsServer
}

// NewAuditLogsHandler returns a new AuditLogsHandler.
func NewAuditLogsHandler(s agpb.AuditLogsServer) *AuditLogsHandler {
	return &AuditLogsHandler{s: s}
}

// ListAuditLogs handles ListAuditLogs HTTP requests.
func (h *AuditLogsHandler) ListAuditLogs(w http.ResponseWriter, r *http.Request) {
	parent := strings.TrimSuffix(r.RequestURI, "/auditlogs")
	req := &apb.ListAuditLogsRequest{Parent: parent}
	resp, err := h.s.ListAuditLogs(r.Context(), req)
	if err != nil {
		httputils.WriteError(w, err)
	}
	httputils.WriteResp(w, resp)
}
