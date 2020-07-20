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
	"testing"
	"time"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
)

var (
	timeStr = time.Date(2020, time.January, 2, 23, 58, 59, 0, time.UTC).Format(time.RFC3339)
)

func Test_parseExp(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  *exp
	}{
		{
			name:  "time >=",
			input: `time >= "` + timeStr + `"`,
			want: &exp{
				field: fieldTime,
				op:    ">=",
				value: timeStr,
			},
		},
		{
			name:  "time <=",
			input: `time <= "` + timeStr + `"`,
			want: &exp{
				field: fieldTime,
				op:    "<=",
				value: timeStr,
			},
		},
		{
			name:  "type",
			input: `type = "REQUEST"`,
			want: &exp{
				field: fieldType,
				op:    "=",
				value: "REQUEST",
			},
		},
		{
			name:  "text =",
			input: `text = "aaa"`,
			want: &exp{
				field: fieldText,
				op:    "=",
				value: "aaa",
			},
		},
		{
			name:  "text :",
			input: `text : "aaa"`,
			want: &exp{
				field: fieldText,
				op:    ":",
				value: "aaa",
			},
		},
		{
			name:  "decision = PASS",
			input: `decision = "PASS"`,
			want: &exp{
				field: fieldDecision,
				op:    "=",
				value: "PASS",
			},
		},
		{
			name:  "decision = pass",
			input: `decision = "pass"`,
			want: &exp{
				field: fieldDecision,
				op:    "=",
				value: "PASS",
			},
		},
		{
			name:  "decision = FAIL",
			input: `decision = "FAIL"`,
			want: &exp{
				field: fieldDecision,
				op:    "=",
				value: "FAIL",
			},
		},
		{
			name:  "decision = fail",
			input: `decision = "fail"`,
			want: &exp{
				field: fieldDecision,
				op:    "=",
				value: "FAIL",
			},
		},
		{
			name:  "trim space",
			input: ` text : "aaa" `,
			want: &exp{
				field: fieldText,
				op:    ":",
				value: "aaa",
			},
		},
		{
			name:  "spaces",
			input: `text   :   "aaa"`,
			want: &exp{
				field: fieldText,
				op:    ":",
				value: "aaa",
			},
		},
		{
			name:  "space in value",
			input: `text = "aa bb"`,
			want: &exp{
				field: fieldText,
				op:    "=",
				value: "aa bb",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseExp(tc.input)
			if err != nil {
				t.Fatalf("parseExp() failed: %v", err)
			}

			if d := cmp.Diff(tc.want, got, cmp.AllowUnexported(exp{})); len(d) > 0 {
				t.Errorf("parseExp() (-want, +got): %s", d)
			}
		})
	}
}

func Test_parseExp_Error(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "unknown field",
			input: `aaa = "bbb"`,
		},
		{
			name:  "time op",
			input: `time = "` + timeStr + `"`,
		},
		{
			name:  "type op",
			input: `type != "REQUEST"`,
		},
		{
			name:  "text op",
			input: `text != "aaa"`,
		},
		{
			name:  "time value",
			input: `time >= "aaa"`,
		},
		{
			name:  "type value",
			input: `type = "aaa"`,
		},
		{
			name:  "decision op",
			input: `decision != "PASS"`,
		},
		{
			name:  "decision value",
			input: `decision = "aaa"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseExp(tc.input); err == nil {
				t.Fatalf("parseExp() wants err")
			}
		})
	}
}

func Test_exp_toCELFilter(t *testing.T) {
	tests := []struct {
		name  string
		input *exp
		want  string
	}{
		{
			name: "time <=",
			input: &exp{
				field: fieldTime,
				op:    lte,
				value: timeStr,
			},
			want: `timestamp <= "` + timeStr + `"`,
		},
		{
			name: "time >=",
			input: &exp{
				field: fieldTime,
				op:    gte,
				value: timeStr,
			},
			want: `timestamp >= "` + timeStr + `"`,
		},
		{
			name: "text =",
			input: &exp{
				field: fieldText,
				op:    equals,
				value: "a",
			},
			want: `(textPayload = "a" OR httpRequest.requestMethod = "a" OR labels.token_id = "a" OR labels.token_issuer = "a" OR labels.tracing_id = "a" OR labels.request_path = "a" OR labels.error_type = "a" OR labels.resource = "a" OR labels.ttl = "a" OR labels.cart_id = "a")`,
		},
		{
			name: "text :",
			input: &exp{
				field: fieldText,
				op:    contains,
				value: "a",
			},
			want: `(textPayload : "a" OR httpRequest.requestMethod : "a" OR labels.token_id : "a" OR labels.token_issuer : "a" OR labels.tracing_id : "a" OR labels.request_path : "a" OR labels.error_type : "a" OR labels.resource : "a" OR labels.ttl : "a" OR labels.cart_id : "a")`,
		},
		{
			name: "type = request",
			input: &exp{
				field: fieldType,
				op:    equals,
				value: "REQUEST",
			},
			want: `labels.type = "request"`,
		},
		{
			name: "type = policy",
			input: &exp{
				field: fieldType,
				op:    equals,
				value: "POLICY",
			},
			want: `labels.type = "policy_decision"`,
		},
		{
			name: "decision = PASS",
			input: &exp{
				field: fieldDecision,
				op:    equals,
				value: "PASS",
			},
			want: `labels.pass_auth_check = "true"`,
		},
		{
			name: "decision = FAIL",
			input: &exp{
				field: fieldDecision,
				op:    equals,
				value: "FAIL",
			},
			want: `labels.pass_auth_check = "false"`,
		},
		{
			name: "escape text =",
			input: &exp{
				field: fieldText,
				op:    equals,
				value: "A\" AND true",
			},
			want: `(textPayload = "A AND true" OR httpRequest.requestMethod = "A AND true" OR labels.token_id = "A AND true" OR labels.token_issuer = "A AND true" OR labels.tracing_id = "A AND true" OR labels.request_path = "A AND true" OR labels.error_type = "A AND true" OR labels.resource = "A AND true" OR labels.ttl = "A AND true" OR labels.cart_id = "A AND true")`,
		},
		{
			name: "escape text :",
			input: &exp{
				field: fieldText,
				op:    contains,
				value: "A\" AND true",
			},
			want: `(textPayload : "A AND true" OR httpRequest.requestMethod : "A AND true" OR labels.token_id : "A AND true" OR labels.token_issuer : "A AND true" OR labels.tracing_id : "A AND true" OR labels.request_path : "A AND true" OR labels.error_type : "A AND true" OR labels.resource : "A AND true" OR labels.ttl : "A AND true" OR labels.cart_id : "A AND true")`,
		},
		{
			name: "escape type",
			input: &exp{
				field: fieldType,
				op:    equals,
				value: "A\" AND true",
			},
			want: `labels.type = ""`,
		},
		{
			name: "escape time",
			input: &exp{
				field: fieldTime,
				op:    gte,
				value: "A\" AND true",
			},
			want: `timestamp >= "A AND true"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.input.toCELFilter()
			if d := cmp.Diff(tc.want, got); len(d) > 0 {
				t.Errorf("toCELFilter() (-want, +got): %s", d)
			}
		})
	}
}

func Test_extractFilters(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "empty input",
			input: "",
			want:  "",
		},
		{
			name:  "all",
			input: fmt.Sprintf(`time >= "%s" AND time <= "%s" AND type = "REQUEST" AND text : "a" AND decision = "PASS"`, timeStr, timeStr),
			want:  `timestamp >= "2020-01-02T23:58:59Z" AND timestamp <= "2020-01-02T23:58:59Z" AND labels.type = "request" AND (textPayload : "a" OR httpRequest.requestMethod : "a" OR labels.token_id : "a" OR labels.token_issuer : "a" OR labels.tracing_id : "a" OR labels.request_path : "a" OR labels.error_type : "a" OR labels.resource : "a" OR labels.ttl : "a" OR labels.cart_id : "a") AND labels.pass_auth_check = "true"`,
		},
		{
			name:  "multi text field",
			input: `text : "a" AND text = "b"`,
			want:  `(textPayload : "a" OR httpRequest.requestMethod : "a" OR labels.token_id : "a" OR labels.token_issuer : "a" OR labels.tracing_id : "a" OR labels.request_path : "a" OR labels.error_type : "a" OR labels.resource : "a" OR labels.ttl : "a" OR labels.cart_id : "a") AND (textPayload = "b" OR httpRequest.requestMethod = "b" OR labels.token_id = "b" OR labels.token_issuer = "b" OR labels.tracing_id = "b" OR labels.request_path = "b" OR labels.error_type = "b" OR labels.resource = "b" OR labels.ttl = "b" OR labels.cart_id = "b")`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := extractFilters(tc.input)
			if err != nil {
				t.Fatalf("extractFilters() failed: %v", err)
			}

			if d := cmp.Diff(tc.want, got); len(d) > 0 {
				t.Errorf("toCELFilter() (-want, +got): %s", d)
			}
		})
	}
}

func Test_extractFilters_Error(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "unknown field",
			input: `aaa = "bbb"`,
		},
		{
			name:  "format",
			input: `aaa = "bbb ccc"`,
		},
		{
			name:  "time op",
			input: `time = "` + timeStr + `"`,
		},
		{
			name:  "type op",
			input: `type != "REQUEST"`,
		},
		{
			name:  "text op",
			input: `text != "aaa"`,
		},
		{
			name:  "time value",
			input: `time >= "aaa"`,
		},
		{
			name:  "type value",
			input: `type = "aaa"`,
		},
		{
			name:  "decision value",
			input: `decision = "aaa"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := extractFilters(tc.input); err == nil {
				t.Fatalf("extractFilters() wants err")
			}
		})
	}
}
