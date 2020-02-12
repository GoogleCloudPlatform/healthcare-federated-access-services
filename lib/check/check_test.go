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

package check

import (
	"testing"

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
)

func TestClientsEqual(t *testing.T) {
	tests := []struct {
		name   string
		input1 map[string]*cpb.Client
		input2 map[string]*cpb.Client
		want   bool
	}{
		{
			name:   "empty input",
			input1: map[string]*cpb.Client{},
			input2: map[string]*cpb.Client{},
			want:   true,
		},
		{
			name: "one item match",
			input1: map[string]*cpb.Client{
				"a": &cpb.Client{ClientId: "aaa"},
			},
			input2: map[string]*cpb.Client{
				"a": &cpb.Client{ClientId: "aaa"},
			},
			want: true,
		},
		{
			name: "one item mismatch",
			input1: map[string]*cpb.Client{
				"a": &cpb.Client{ClientId: "aaa"},
			},
			input2: map[string]*cpb.Client{
				"a": &cpb.Client{ClientId: "bbb"},
			},
			want: false,
		},
		{
			name: "two item match",
			input1: map[string]*cpb.Client{
				"a": &cpb.Client{ClientId: "aaa"},
				"b": &cpb.Client{ClientId: "bbb"},
			},
			input2: map[string]*cpb.Client{
				"a": &cpb.Client{ClientId: "aaa"},
				"b": &cpb.Client{ClientId: "bbb"},
			},
			want: true,
		},
		{
			name: "partial list mismatch",
			input1: map[string]*cpb.Client{
				"a": &cpb.Client{ClientId: "aaa"},
				"b": &cpb.Client{ClientId: "bbb"},
			},
			input2: map[string]*cpb.Client{
				"a": &cpb.Client{ClientId: "aaa"},
			},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ClientsEqual(tc.input1, tc.input2)
			if got != tc.want {
				t.Errorf("test %q: CheckClientsEqual(%v, %v) = %v, want %v", tc.name, tc.input1, tc.input2, got, tc.want)
			}
		})
	}
}
