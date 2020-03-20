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
	"net/url"
	"regexp"
	"strings"

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
)

// extractFilters validates the filters and returns a Stackdriver Logging filter.
// Currently supports a conjunction of time expressions.
// time corresponds to to Stackdriver Logging field timestamp.
// For guidance on filtering see: https://aip.dev/160
func extractFilters(in string) (string, error) {
	// TODO: consider using CEL: https://github.com/google/cel-spec
	if in == "" {
		return "", nil
	}
	f, err := url.QueryUnescape(in)
	if err != nil {
		status.Errorf(codes.InvalidArgument, "invalid filter %q", in)
	}
	if !timeFilterRE.MatchString(f) {
		return "", status.Errorf(codes.InvalidArgument, "invalid filter %q", in)
	}
	return strings.ReplaceAll(f, "time", "timestamp"), nil
}

var (
	rfc3339REStr = `\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[A-Z]?(?:[+.-]?(?:\d{2}|\d{2}:\d{2})[A-Z]?)?`
	expREStr     = `time(=|!=|<|>|<=|>=)` + rfc3339REStr
	timeFilterRE = regexp.MustCompile(`^` + expREStr + `( AND ` + expREStr + `)*` + `$`)
)
