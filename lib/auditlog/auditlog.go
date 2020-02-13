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

// Package auditlog contains logging structs.
package auditlog

import (
	"context"
	"net/http"

	"cloud.google.com/go/logging" /* copybara-comment: logging */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/serviceinfo" /* copybara-comment: serviceinfo */

	mrpb "google.golang.org/genproto/googleapis/api/monitoredres" /* copybara-comment */
)

// AccessLog logs the http endpoint accessing.
type AccessLog struct {
	// TokenID is the id of the token, maybe "jti".
	TokenID string
	// TokenSubject is the "sub" of the token.
	TokenSubject string
	// RequestMethod is the http method of the request.
	RequestMethod string
	// RequestEndpoint is the absolute path of the request.
	RequestEndpoint string
	// RequestIP is the requester IP.
	RequestIP string
	// ErrorType formats like "no_token" for search.
	ErrorType string
	// ResponseCode is the response code.
	ResponseCode int
	// Request stores the http.Request.
	Request *http.Request
	// Payload of the log.
	Payload interface{}
}

// WriteAccessLog puts the access log to StackDriver.
func WriteAccessLog(ctx context.Context, client *logging.Client, log *AccessLog) {
	l := client.Logger("federated-access-audit")

	labels := map[string]string{
		"type":          "access_log",
		"token_id":      log.TokenID,
		"token_subject": log.TokenSubject,
		"request_path":  log.RequestEndpoint,
		"error_type":    log.ErrorType,
	}

	req := &logging.HTTPRequest{
		Request:  log.Request,
		RemoteIP: log.RequestIP,
		Status:   log.ResponseCode,
	}

	entry := logging.Entry{
		Labels:      labels,
		Payload:     log.Payload,
		HTTPRequest: req,
		Resource:    buildResource(),
	}

	l.Log(entry)
}

func buildResource() *mrpb.MonitoredResource {
	return &mrpb.MonitoredResource{
		Type: "github.com/GoogleCloudPlatform/healthcare-federated-access-services",
		Labels: map[string]string{
			"project_id":   serviceinfo.Project,
			"service_type": serviceinfo.Type,
			"service_name": serviceinfo.Name,
		},
	}
}
