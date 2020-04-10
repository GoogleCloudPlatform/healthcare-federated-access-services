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
	"regexp"
	"time"
)

const (
	// iamVersion use 3 to support iam condition.
	iamVersion = 3
)

var (
	expiryConditionRE   = regexp.MustCompile(`^request\.time < timestamp\("(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\"\)$`)
	expiryTimeFormat    = "2006-01-02T15:04:05Z"
	conditionExprFormat = `request.time < timestamp("%s")`
	timeNow             = time.Now
)

// expiryInCondition finds expiry in condition expression
func expiryInCondition(condition string) time.Time {
	if len(condition) == 0 {
		return time.Time{}
	}
	match := expiryConditionRE.FindStringSubmatch(condition)
	if len(match) > 1 {
		if ts, err := time.Parse(expiryTimeFormat, match[1]); err == nil {
			return ts
		}
	}

	return time.Time{}
}

// toExpiryConditionExpr builds the condition expr with given timestamp
func toExpiryConditionExpr(exp time.Time) string {
	timeStr := exp.Format(expiryTimeFormat)
	return fmt.Sprintf(conditionExprFormat, timeStr)
}
