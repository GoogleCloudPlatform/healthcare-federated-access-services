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
	"strconv"

	"cloud.google.com/go/logging" /* copybara-comment: logging */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/globalflags" /* copybara-comment: globalflags */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/serviceinfo" /* copybara-comment: serviceinfo */

	glog "github.com/golang/glog" /* copybara-comment */
)

// AccessLog logs the http endpoint accessing.
type AccessLog struct {
	// TokenID is the id of the token, maybe "jti".
	TokenID string
	// TokenSubject is the "sub" of the token.
	TokenSubject string
	// TokenIssuer is the iss of the token.
	TokenIssuer string
	// TracingID is the id of request from proxies.
	TracingID string
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
	// PassAuthCheck if the request pass the auth checker.
	PassAuthCheck bool
	// Payload of the log.
	Payload interface{}
}

// WriteAccessLog puts the access log to StackDriver.
func WriteAccessLog(ctx context.Context, client *logging.Client, log *AccessLog) {
	labels := map[string]string{
		"type":            "access_log",
		"token_id":        log.TokenID,
		"token_subject":   log.TokenSubject,
		"token_issuer":    log.TokenIssuer,
		"tracing_id":      log.TracingID,
		"request_path":    log.RequestEndpoint,
		"error_type":      log.ErrorType,
		"pass_auth_check": strconv.FormatBool(log.PassAuthCheck),
		"project_id":      serviceinfo.Project,
		"service_type":    serviceinfo.Type,
		"service_name":    serviceinfo.Name,
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
	}

	writeLog(client, entry)
}

func writeLog(client *logging.Client, e logging.Entry) {
	if globalflags.DisableAuditLog {
		return
	}

	if client == nil {
		glog.Info("no logging client is provided for audit logging")
		return
	}

	client.Logger("federated-access-audit").Log(e)
}
