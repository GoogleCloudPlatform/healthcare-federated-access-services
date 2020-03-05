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

package httputils

// This file contains utilities for resource names in the request.
// TODO: not related to http, move to a more appripriate package.

import (
	"fmt"
	"regexp"
)

// CheckName checks name for a field satisfies the naming rules for it.
func CheckName(field, name string, regexps map[string]*regexp.Regexp) error {
	if len(name) == 0 {
		return fmt.Errorf("invalid %s: empty", field)
	}

	re := lookupFieldRE(field, regexps)

	if !re.Match([]byte(name)) {
		return fmt.Errorf("invalid %s: %q is too long, too short, or contains invalid characters", field, name)
	}
	return nil
}

var (
	nameRE     = regexp.MustCompile(`^[A-Za-z][-_A-Za-z0-9\.]{1,30}[A-Za-z0-9]$`)
	longNameRE = regexp.MustCompile(`^[A-Za-z][-_A-Za-z0-9\.]{1,46}[A-Za-z0-9]$`)
)

func lookupFieldRE(field string, res map[string]*regexp.Regexp) *regexp.Regexp {
	if res == nil {
		res = make(map[string]*regexp.Regexp)
	}

	// TODO: move this block to caller.
	if _, ok := res["realm"]; !ok {
		res["realm"] = longNameRE
	}

	if r, ok := res[field]; ok {
		return r
	}

	return nameRE
}

// IsJSON returns true when the data format is JSON.
func IsJSON(str string) bool {
	return str == "application/json" || str == "JSON" || str == "json"
}
