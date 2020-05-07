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

	"github.com/gorilla/mux" /* copybara-comment */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/handlerfactory" /* copybara-comment: handlerfactory */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */

	apb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/auditlogs/v0" /* copybara-comment: auditlogs_go_proto */
)

// ListAuditlogsPathFactory creates a http handler for "/identity/v1alpha/users/{user}/auditlogs"
func ListAuditlogsPathFactory(auditlogsPath string, logs *AuditLogs) *handlerfactory.Options {
	return &handlerfactory.Options{
		TypeName:            "auditlogs",
		PathPrefix:          auditlogsPath,
		HasNamedIdentifiers: false,
		Service: func() handlerfactory.Service {
			return &listAuditlogsHandler{logs: logs}
		},
	}
}

type listAuditlogsHandler struct {
	handlerfactory.Empty
	logs *AuditLogs
}

func (s *listAuditlogsHandler) Get(r *http.Request, name string) (proto.Message, error) {
	userID, ok := mux.Vars(r)["user"]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "user id is missing")
	}

	size := httputils.QueryParamInt(r, "page_size")
	if size <= 0 {
		return nil, status.Error(codes.InvalidArgument, "param page_size is missing or invalid")
	}

	pageToken := httputils.QueryParam(r, "page_token")
	filter := httputils.QueryParam(r, "filter")

	return s.logs.ListAuditLogs(r.Context(), &apb.ListAuditLogsRequest{
		UserId:    userID,
		Filter:    filter,
		PageSize:  int32(size),
		PageToken: pageToken,
	})
}
