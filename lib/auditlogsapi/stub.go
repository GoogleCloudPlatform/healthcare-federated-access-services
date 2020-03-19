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

	glog "github.com/golang/glog" /* copybara-comment */
	apb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/auditlogs/v0" /* copybara-comment: auditlogs_go_proto */
)

// Stub is a stub implementation.
type Stub struct {
	AuditLog *apb.AuditLog
}

// ListAuditLogs lists the AuditLogs.
func (s *Stub) ListAuditLogs(_ context.Context, req *apb.ListAuditLogsRequest) (*apb.ListAuditLogsResponse, error) {
	glog.Infof("ListAuditLogs %v", req)
	return &apb.ListAuditLogsResponse{AuditLogs: []*apb.AuditLog{s.AuditLog}}, nil
}

// FakeAuditLog is a fake token.
// TODO: move these fakes to test file once implemented.
var FakeAuditLog = &apb.AuditLog{}
