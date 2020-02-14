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

package ga4gh

import (
	"encoding/json"
)

// Audiences is "aud" field in jwt. In oidc spec, "aud" can be single string
// or array of string.
// https://tools.ietf.org/html/rfc7519#section-4.1.3
type Audiences []string

// NewAudience returns Audiences based on a single string input.
func NewAudience(aud string) Audiences {
	if len(aud) == 0 {
		return nil
	}
	return Audiences{aud}
}

// UnmarshalJSON unmarshal string or array of string in json to []string in go.
func (a *Audiences) UnmarshalJSON(bytes []byte) error {
	var s string
	if err := json.Unmarshal(bytes, &s); err == nil {
		*a = []string{s}
		return nil
	}

	var ss []string
	err := json.Unmarshal(bytes, &ss)
	if err == nil {
		if len(ss) != 0 {
			*a = ss
		} else {
			*a = nil
		}
		return nil
	}
	return err
}
