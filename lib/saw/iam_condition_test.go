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

package saw

import (
	"fmt"
	"testing"
	"time"
)

func Test_expiryInCondition(t *testing.T) {
	tsStr := "2021-01-02T03:04:05Z"
	ts, err := time.Parse(expiryTimeFormat, tsStr)
	if err != nil {
		t.Fatalf("time.Parse() failed: %v", err)
	}

	tests := []struct {
		name string
		expr string
		want time.Time
	}{
		{
			name: "ok",
			expr: fmt.Sprintf(`request.time < timestamp("%s")`, tsStr),
			want: ts,
		},
		{
			name: "empty condition",
			expr: ``,
			want: time.Time{},
		},
		{
			name: "invalid condition",
			expr: `request.time < timestamp(2020)`,
			want: time.Time{},
		},
		{
			name: "invalid timestr",
			expr: `request.time < timestamp(2020-01-60T50:00:00Z")`,
			want: time.Time{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := expiryInCondition(tc.expr)
			if !got.Equal(tc.want) {
				t.Errorf("expiryInCondition(%s) = %v, wants %v", tc.expr, got, tc.want)
			}
		})
	}
}

func Test_toExpiryConditionExpr(t *testing.T) {
	tsStr := "2021-01-02T03:04:05Z"
	ts, err := time.Parse(expiryTimeFormat, tsStr)
	if err != nil {
		t.Fatalf("time.Parse() failed: %v", err)
	}

	want := `request.time < timestamp("2021-01-02T03:04:05Z")`
	got := toExpiryConditionExpr(ts)
	if got != want {
		t.Errorf("toExpiryConditionExpr() = %s, wants %s", got, want)
	}
}
