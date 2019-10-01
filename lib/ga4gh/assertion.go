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

// Assertion represents a GA4GH Passport Visa Object.
// http://bit.ly/ga4gh-passport-v1#passport-visa-object
type Assertion struct {
	// Type http://bit.ly/ga4gh-passport-v1#type
	Type Type `json:"type,omitempty"`

	// Value http://bit.ly/ga4gh-passport-v1#value
	Value Value `json:"value,omitempty"`

	// Source http://bit.ly/ga4gh-passport-v1#source
	Source Source `json:"source,omitempty"`

	// By http://bit.ly/ga4gh-passport-v1#by
	By By `json:"by,omitempty"`

	// Asserted http://bit.ly/ga4gh-passport-v1#asserted
	Asserted Timestamp `json:"asserted,omitempty"`

	// Conditions http://bit.ly/ga4gh-passport-v1#conditions
	Conditions Conditions `json:"conditions,omitempty"`
}
