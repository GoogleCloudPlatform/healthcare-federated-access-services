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

// Conditions represents a GA4GH Passport Visa condition field sub-object.
// https://docs.google.com/document/d/1NySsYM1V9ssxk_k4RH37fU4tJK8x37YMmDxnn_45FvQ/
type Conditions [][]Condition

// Condition represnet a GA4GH Passport Visa Condition.
type Condition struct {
	Type   string `json:"type,omitempty"`
	Value  string `json:"value,omitempty"`
	Source string `json:"source,omitempty"`
	By     string `json:"by,omitempty"`
}
