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

var (
	// LogSync ensure that logs are written sync.
	// Useful for testing.
	LogSync bool

	// SearchableFields lists all labels allow to search via FA endpoints
	SearchableFields = []string{
		"httpRequest.requestMethod",
		"labels.token_id",
		"labels.token_issuer",
		"labels.tracing_id",
		"labels.request_endpoint",
		"labels.request_path",
		"labels.error_type",
		"labels.resource",
		"labels.ttl",
		"labels.cart_id",
	}
)

const (
	// TypeRequestLog log type string for access log
	TypeRequestLog = "request"
	// TypePolicyLog log type string for policy log
	TypePolicyLog = "policy_decision"
)

// RequestLog logs the http endpoint accessing.
type RequestLog struct {
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
	// RequestEndpoint is the absolute abstract path of the request endpoint registration.
	RequestEndpoint string
	// RequestPath is the request's path with concrete variables (such as realm) filled in
	// as per the caller's absolute path.
	RequestPath string
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

// WriteRequestLog puts the access log to StackDriver.
func WriteRequestLog(ctx context.Context, client *logging.Client, log *RequestLog) {
	labels := map[string]string{
		"type":             TypeRequestLog,
		"token_id":         log.TokenID,
		"token_subject":    log.TokenSubject,
		"token_issuer":     log.TokenIssuer,
		"tracing_id":       log.TracingID,
		"request_endpoint": log.RequestEndpoint,
		"request_path":     log.RequestPath,
		"error_type":       log.ErrorType,
		"pass_auth_check":  strconv.FormatBool(log.PassAuthCheck),
		"project_id":       serviceinfo.Project,
		"service_type":     serviceinfo.Type,
		"service_name":     serviceinfo.Name,
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

// PolicyDecisionLog logs the dataset access request be granted or denied and the reason.
type PolicyDecisionLog struct {
	// TokenID is the id of the token, maybe "jti".
	TokenID string
	// TokenSubject is the "sub" of the token.
	TokenSubject string
	// TokenIssuer is the iss of the token.
	TokenIssuer string
	// Resource identifies the dataset.
	Resource string
	// TTL that user requested to grant.
	TTL string
	// PassAuthCheck if the request pass the auth checker.
	PassAuthCheck bool
	// ErrorType of deny.
	ErrorType string
	// CartID of request.
	CartID string
	// ConfigRevision the request using. Can use /config/history/{revision} to see the policy.
	ConfigRevision int64
	// Message of deny.
	Message interface{}
}

// WritePolicyDecisionLog puts the policy decision log to StackDriver.
func WritePolicyDecisionLog(client *logging.Client, log *PolicyDecisionLog) {
	labels := map[string]string{
		"type":            TypePolicyLog,
		"token_id":        log.TokenID,
		"token_subject":   log.TokenSubject,
		"token_issuer":    log.TokenIssuer,
		"pass_auth_check": strconv.FormatBool(log.PassAuthCheck),
		"error_type":      log.ErrorType,
		"resource":        log.Resource,
		"ttl":             log.TTL,
		"project_id":      serviceinfo.Project,
		"service_type":    serviceinfo.Type,
		"service_name":    serviceinfo.Name,
		"cart_id":         log.CartID,
		"config_revision": strconv.FormatInt(log.ConfigRevision, 10),
	}

	entry := logging.Entry{
		Labels:  labels,
		Payload: log.Message,
	}

	writeLog(client, entry)
}

func writeLog(client *logging.Client, e logging.Entry) {
	ctx := context.Background() /* TODO: pass context to here */
	if globalflags.DisableAuditLog {
		return
	}

	if client == nil {
		glog.Info("no logging client is provided for audit logging")
		return
	}

	if LogSync {
		client.Logger("federated-access-audit").LogSync(ctx, e)
	} else {
		client.Logger("federated-access-audit").Log(e)
	}
}
