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

package storage

import (
	"testing"

	"github.com/golang/protobuf/proto" /* copybara-comment */
)

func TestFilters(t *testing.T) {
	fields := map[string]func(p proto.Message) string{
		"apple": func(p proto.Message) string {
			return "APPLES"
		},
		"orange": func(p proto.Message) string {
			return ""
		},
		"test.fruit": func(p proto.Message) string {
			return "FRUIT"
		},
	}
	tests := []struct {
		input string
		want  []Filter
		ok    bool
	}{
		{
			input: `apple sw "mac"`,
			want: []Filter{
				{
					compare: "sw",
					value:   "mac",
				},
			},
			ok: false,
		},
		{
			input: `apple eq "apples"`,
			want: []Filter{
				{
					compare: "eq",
					value:   "apples",
				},
			},
			ok: true,
		},
		{
			input: `Apple Eq "Apples"`,
			want: []Filter{
				{
					compare: "eq",
					value:   "apples",
				},
			},
			ok: true,
		},
		{
			input: `apple ne "apples"`,
			want: []Filter{
				{
					compare: "ne",
					value:   "apples",
				},
			},
			ok: false,
		},
		{
			input: `apple ne "apple"`,
			want: []Filter{
				{
					compare: "ne",
					value:   "apple",
				},
			},
			ok: true,
		},
		{
			input: `apple ne "apples"`,
			want: []Filter{
				{
					compare: "ne",
					value:   "apples",
				},
			},
			ok: false,
		},
		{
			input: `apple co "pp"`,
			want: []Filter{
				{
					compare: "co",
					value:   "pp",
				},
			},
			ok: true,
		},
		{
			input: `apple co "ppp"`,
			want: []Filter{
				{
					compare: "co",
					value:   "ppp",
				},
			},
			ok: false,
		},
		{
			input: `apple sw "app"`,
			want: []Filter{
				{
					compare: "sw",
					value:   "app",
				},
			},
			ok: true,
		},
		{
			input: `apple sw "pples"`,
			want: []Filter{
				{
					compare: "sw",
					value:   "pples",
				},
			},
			ok: false,
		},
		{
			input: `apple ew "pples"`,
			want: []Filter{
				{
					compare: "ew",
					value:   "pples",
				},
			},
			ok: true,
		},
		{
			input: `apple ew "apple"`,
			want: []Filter{
				{
					compare: "ew",
					value:   "apple",
				},
			},
			ok: false,
		},
		{
			input: `apple pr ""`,
			want: []Filter{
				{
					compare: "pr",
					value:   "",
				},
			},
			ok: true,
		},
		{
			input: `orange pr ""`,
			want: []Filter{
				{
					compare: "pr",
					value:   "",
				},
			},
			ok: false,
		},
		{
			input: `apple gt "AAA"`,
			want: []Filter{
				{
					compare: "gt",
					value:   "aaa",
				},
			},
			ok: true,
		},
		{
			input: `apple gt "ZZZ"`,
			want: []Filter{
				{
					compare: "gt",
					value:   "zzz",
				},
			},
			ok: false,
		},
		{
			input: `apple ge "AAA"`,
			want: []Filter{
				{
					compare: "ge",
					value:   "aaa",
				},
			},
			ok: true,
		},
		{
			input: `apple ge "APP"`,
			want: []Filter{
				{
					compare: "ge",
					value:   "app",
				},
			},
			ok: true,
		},
		{
			input: `apple ge "APQ"`,
			want: []Filter{
				{
					compare: "ge",
					value:   "apq",
				},
			},
			ok: false,
		},
		{
			input: `apple lt "ZZZ"`,
			want: []Filter{
				{
					compare: "lt",
					value:   "zzz",
				},
			},
			ok: true,
		},
		{
			input: `apple lt "APP"`,
			want: []Filter{
				{
					compare: "lt",
					value:   "app",
				},
			},
			ok: false,
		},
		{
			input: `apple le "ZZZ"`,
			want: []Filter{
				{
					compare: "le",
					value:   "zzz",
				},
			},
			ok: true,
		},
		{
			input: `apple le "APQ"`,
			want: []Filter{
				{
					compare: "le",
					value:   "apq",
				},
			},
			ok: true,
		},
		{
			input: `apple le "APP"`,
			want: []Filter{
				{
					compare: "le",
					value:   "app",
				},
			},
			ok: false,
		},
		{
			input: `test.fruit co "apples" or apple ne "mac"`,
			want: []Filter{
				{
					compare: "co",
					value:   "apples",
				},
				{
					compare: "ne",
					value:   "mac",
				},
			},
			ok: true,
		},
	}

	for _, tc := range tests {
		f, err := BuildFilters(tc.input, fields)
		if err != nil {
			t.Fatalf("BuildFilters(%q, fields) = (%v, %v), unexpected error", tc.input, f, err)
		}
		// TODO: attempt to get cmp.Diff() working with these structures
		if len(f) != len(tc.want) {
			t.Fatalf("BuildFilters(%q, fields) = %+v, want %+v length %d", tc.input, f, tc.want, len(tc.want))
		}
		for i := 0; i < len(f); i++ {
			if f[i].compare != tc.want[i].compare {
				t.Fatalf("BuildFilters(%q, fields) = %+v, filter %d compare: want %q, got %q", tc.input, f, i, tc.want[i].compare, f[i].compare)
			}
			if f[i].value != tc.want[i].value {
				t.Fatalf("BuildFilters(%q, fields) = %+v, filter %d value: want %q, got %q", tc.input, f, i, tc.want[i].value, f[i].value)
			}
		}
		if ok := MatchProtoFilters(f, nil); tc.ok != ok {
			t.Errorf("MatchProtoFilters(%v, nil) = %v, want %v", f, ok, tc.ok)
		}
	}
}
