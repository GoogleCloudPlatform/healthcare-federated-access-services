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
	"fmt"
	"regexp"
	"strings"
	"time"

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/auditlog" /* copybara-comment: auditlog */

	apb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/auditlogs/v0" /* copybara-comment: auditlogs_go_proto */
)

var (
	// Warning: adding allow characters could lead to injection, need to double check valueEscape().
	expRE = regexp.MustCompile(`(type|time|text|decision)\s*(=|>=|<=|:)\s*\"([\s\(\)\.\-\+,'#@;%:_/0-9A-Za-z]+)\"`)
)

// extractFilters validates the filters and returns a Stackdriver Logging filter.
// Currently supports a conjunction of time expressions.
// time corresponds to to Stackdriver Logging field timestamp.
// For guidance on filtering see: https://aip.dev/160
func extractFilters(in string) (string, error) {
	if in == "" {
		return "", nil
	}

	var exps []*exp
	for _, ss := range strings.Split(in, " AND ") {
		e, err := parseExp(ss)
		if err != nil {
			return "", err
		}
		exps = append(exps, e)
	}

	return toCELFilter(exps), nil
}

func parseExp(s string) (*exp, error) {
	s = strings.TrimSpace(s)
	matches := expRE.FindAllStringSubmatch(s, -1)
	if len(matches) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "unknown expression format")
	}
	ss := matches[0][1:]

	var field expField
	for _, f := range allowFields {
		if ss[0] == string(f) {
			field = f
		}
	}
	if len(field) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "unknown expression field: %s", ss[0])
	}

	switch field {
	case fieldTime:
		// time allows >= and <=
		if ss[1] != string(gte) && ss[1] != string(lte) {
			return nil, status.Errorf(codes.InvalidArgument, "not allowed op for time field: %s", ss[1])
		}
	case fieldType:
		// type allows =
		if ss[1] != string(equals) {
			return nil, status.Errorf(codes.InvalidArgument, "not allowed op for type field: %s", ss[1])
		}
	case fieldText:
		// text allows : and =
		if ss[1] != string(equals) && ss[1] != string(contains) {
			return nil, status.Errorf(codes.InvalidArgument, "not allowed op for text field: %s", ss[1])
		}
	case fieldDecision:
		// decision allows =
		if ss[1] != string(equals) {
			return nil, status.Errorf(codes.InvalidArgument, "not allowed op for decision field: %s", ss[1])
		}
	default:
		return nil, status.Errorf(codes.Internal, "unknown expression field in op checker: %s", field)
	}

	op := expOp(ss[1])

	value := strings.Trim(ss[2], `"`)

	if field == fieldTime {
		if _, err := time.Parse(time.RFC3339, value); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "time value not in RFC3339 format: %s", value)
		}
	}

	if field == fieldType {
		if value != apb.LogType_REQUEST.String() && value != apb.LogType_POLICY.String() {
			return nil, status.Errorf(codes.InvalidArgument, "type value not allowed: %s", value)
		}
	}

	if field == fieldDecision {
		value = strings.ToUpper(value)
		if value != apb.Decision_PASS.String() && value != apb.Decision_FAIL.String() {
			return nil, status.Errorf(codes.InvalidArgument, "decision value not allowed: %s", value)
		}
	}

	return &exp{field: field, op: op, value: value}, nil
}

// exp : expression support from request
type exp struct {
	field expField
	op    expOp
	value string
}

func (s *exp) toCELFilter() string {
	value := valueEscape(s.value)

	switch s.field {
	case fieldTime:
		return fmt.Sprintf(`timestamp %s "%s"`, s.op, value)
	case fieldType:
		return fmt.Sprintf(`labels.type = "%s"`, toAuditLogType(value))
	case fieldText:
		return toTextFilter(s.op, value)
	case fieldDecision:
		return fmt.Sprintf(`labels.pass_auth_check = "%s"`, toDecisionValue(value))
	default:
		return ""
	}
}

func toCELFilter(exps []*exp) string {
	var ss []string
	for _, e := range exps {
		ss = append(ss, e.toCELFilter())
	}

	return strings.Join(ss, " AND ")
}

func toAuditLogType(ty string) string {
	switch ty {
	case apb.LogType_REQUEST.String():
		return auditlog.TypeRequestLog
	case apb.LogType_POLICY.String():
		return auditlog.TypePolicyLog
	default:
		return ""
	}
}

func toTextFilter(op expOp, value string) string {
	list := []string{
		fmt.Sprintf(`textPayload %s "%s"`, op, value),
	}
	for _, l := range auditlog.SearchableLabels {
		list = append(list, fmt.Sprintf(`labels.%s %s "%s"`, l, op, value))
	}

	s := strings.Join(list, " OR ")
	return "(" + s + ")"
}

func toDecisionValue(v string) string {
	switch v {
	case apb.Decision_PASS.String():
		return "true"
	case apb.Decision_FAIL.String():
		return "false"
	default:
		return ""
	}
}

// valueEscape removes double quotes to ensure no injection.
func valueEscape(s string) string {
	s = strings.ReplaceAll(s, `"`, ``)

	return s
}

type expField string
type expOp string

var (
	fieldTime     expField = "time"
	fieldText     expField = "text"
	fieldType     expField = "type"
	fieldDecision expField = "decision"

	allowFields = []expField{fieldTime, fieldText, fieldType, fieldDecision}

	equals   expOp = "="
	contains expOp = ":"
	gte      expOp = ">="
	lte      expOp = "<="
)
