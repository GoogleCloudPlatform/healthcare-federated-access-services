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
	"strings"

	glog "github.com/golang/glog" /* copybara-comment */
	lgrpcpb "google.golang.org/genproto/googleapis/logging/v2" /* copybara-comment: logging_go_grpc */
	lpb "google.golang.org/genproto/googleapis/logging/v2" /* copybara-comment: logging_go_proto */
	apb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/auditlogs/v0" /* copybara-comment: auditlogs_go_proto */
)

// AuditLogs is implments the audit logs API for DAM.
// Currently support GCP tokens.
type AuditLogs struct {
	// sdl is the Stackdriver Logging Client.
	sdl lgrpcpb.LoggingServiceV2Client

	// projectID identifies the GCP project where the auditlogs are located.
	projectID string

	// serviceName of current instance
	serviceName string
}

// NewAuditLogs creates a new AuditLogs.
func NewAuditLogs(sdl lgrpcpb.LoggingServiceV2Client, projectID, serviceName string) *AuditLogs {
	return &AuditLogs{sdl: sdl, projectID: projectID, serviceName: serviceName}
}

// ListAuditLogs lists the audit logs.
func (s *AuditLogs) ListAuditLogs(ctx context.Context, req *apb.ListAuditLogsRequest) (*apb.ListAuditLogsResponse, error) {
	filters := []string{
		`logName="projects/` + s.projectID + `/logs/federated-access-audit"`,
		`labels.token_subject="` + req.UserId + `"`,
		`labels.service_name="` + s.serviceName + `"`,
	}

	f, err := extractFilters(req.Filter)
	if err != nil {
		return nil, err
	}

	if len(f) > 0 {
		filters = append(filters, f)
	}

	sdlReq := &lpb.ListLogEntriesRequest{
		ResourceNames: []string{"projects/" + s.projectID},
		PageSize:      req.PageSize,
		PageToken:     req.PageToken,
		OrderBy:       "timestamp desc",
		Filter:        strings.Join(filters, " AND "),
	}
	sdlResp, err := s.sdl.ListLogEntries(ctx, sdlReq)
	if err != nil {
		return nil, err
	}
	resp := &apb.ListAuditLogsResponse{}
	for _, e := range sdlResp.GetEntries() {
		a, err := ToAuditLog(e)
		if err != nil {
			glog.Warningf("ToAuditLog() failed: %v", err)
			continue
		}
		resp.AuditLogs = append(resp.AuditLogs, a)
	}
	return resp, nil
}
