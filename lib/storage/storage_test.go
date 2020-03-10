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

	"google3/third_party/golang/protobuf/v1/proto/proto"
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
		"active": func(p proto.Message) string {
			return "true"
		},
	}
	tests := []struct {
		input string
		want  [][]Filter
		ok    bool
	}{
		{
			input: `apple sw "mac"`,
			want: [][]Filter{
				{
					{
						compare: "sw",
						value:   "mac",
					},
				},
			},
			ok: false,
		},
		{
			input: `apple eq "apples"`,
			want: [][]Filter{
				{
					{
						compare: "eq",
						value:   "apples",
					},
				},
			},
			ok: true,
		},
		{
			input: `Apple Eq "Apples"`,
			want: [][]Filter{
				{
					{
						compare: "eq",
						value:   "apples",
					},
				},
			},
			ok: true,
		},
		{
			input: `apple ne "apples"`,
			want: [][]Filter{
				{
					{
						compare: "ne",
						value:   "apples",
					},
				},
			},
			ok: false,
		},
		{
			input: `apple ne "apple"`,
			want: [][]Filter{
				{
					{
						compare: "ne",
						value:   "apple",
					},
				},
			},
			ok: true,
		},
		{
			input: `apple ne "apples"`,
			want: [][]Filter{
				{
					{
						compare: "ne",
						value:   "apples",
					},
				},
			},
			ok: false,
		},
		{
			input: `apple co "pp"`,
			want: [][]Filter{
				{
					{
						compare: "co",
						value:   "pp",
					},
				},
			},
			ok: true,
		},
		{
			input: `apple co "ppp"`,
			want: [][]Filter{
				{
					{
						compare: "co",
						value:   "ppp",
					},
				},
			},
			ok: false,
		},
		{
			input: `apple sw "app"`,
			want: [][]Filter{
				{
					{
						compare: "sw",
						value:   "app",
					},
				},
			},
			ok: true,
		},
		{
			input: `apple sw "pples"`,
			want: [][]Filter{
				{
					{
						compare: "sw",
						value:   "pples",
					},
				},
			},
			ok: false,
		},
		{
			input: `apple ew "pples"`,
			want: [][]Filter{
				{
					{
						compare: "ew",
						value:   "pples",
					},
				},
			},
			ok: true,
		},
		{
			input: `apple ew "apple"`,
			want: [][]Filter{
				{
					{
						compare: "ew",
						value:   "apple",
					},
				},
			},
			ok: false,
		},
		{
			input: `apple pr ""`,
			want: [][]Filter{
				{
					{
						compare: "pr",
						value:   "",
					},
				},
			},
			ok: true,
		},
		{
			input: `orange pr ""`,
			want: [][]Filter{
				{
					{
						compare: "pr",
						value:   "",
					},
				},
			},
			ok: false,
		},
		{
			input: `apple gt "AAA"`,
			want: [][]Filter{
				{
					{
						compare: "gt",
						value:   "aaa",
					},
				},
			},
			ok: true,
		},
		{
			input: `apple gt "ZZZ"`,
			want: [][]Filter{
				{
					{
						compare: "gt",
						value:   "zzz",
					},
				},
			},
			ok: false,
		},
		{
			input: `apple ge "AAA"`,
			want: [][]Filter{
				{
					{
						compare: "ge",
						value:   "aaa",
					},
				},
			},
			ok: true,
		},
		{
			input: `apple ge "APP"`,
			want: [][]Filter{
				{
					{
						compare: "ge",
						value:   "app",
					},
				},
			},
			ok: true,
		},
		{
			input: `apple ge "APQ"`,
			want: [][]Filter{
				{
					{
						compare: "ge",
						value:   "apq",
					},
				},
			},
			ok: false,
		},
		{
			input: `apple lt "ZZZ"`,
			want: [][]Filter{
				{
					{
						compare: "lt",
						value:   "zzz",
					},
				},
			},
			ok: true,
		},
		{
			input: `apple lt "APP"`,
			want: [][]Filter{
				{
					{
						compare: "lt",
						value:   "app",
					},
				},
			},
			ok: false,
		},
		{
			input: `apple le "ZZZ"`,
			want: [][]Filter{
				{
					{
						compare: "le",
						value:   "zzz",
					},
				},
			},
			ok: true,
		},
		{
			input: `apple le "APQ"`,
			want: [][]Filter{
				{
					{
						compare: "le",
						value:   "apq",
					},
				},
			},
			ok: true,
		},
		{
			input: `apple le "APP"`,
			want: [][]Filter{
				{
					{
						compare: "le",
						value:   "app",
					},
				},
			},
			ok: false,
		},
		{
			input: `active eq true`,
			want: [][]Filter{
				{
					{compare: "eq", value: "true"},
				},
			},
			ok: true,
		},
		{
			input: `active ne true`,
			want: [][]Filter{
				{
					{compare: "ne", value: "true"},
				},
			},
			ok: false,
		},
		{
			input: `active eq false`,
			want: [][]Filter{
				{
					{compare: "eq", value: "false"},
				},
			},
			ok: false,
		},
		{
			input: `test.fruit co "apples" or apple ne "mac"`,
			want: [][]Filter{
				{
					{
						compare: "co",
						value:   "apples",
					},
					{
						compare: "ne",
						value:   "mac",
					},
				},
			},
			ok: true,
		},
		{
			input: `apple co "apples" and orange ne "foo"`,
			want: [][]Filter{
				{
					{
						compare: "co",
						value:   "apples",
					},
				},
				{
					{
						compare: "ne",
						value:   "foo",
					},
				},
			},
			ok: true,
		},
		{
			input: `(apple co "apples") and orange ne "foo"`,
			want: [][]Filter{
				{
					{
						compare: "co",
						value:   "apples",
					},
				},
				{
					{
						compare: "ne",
						value:   "foo",
					},
				},
			},
			ok: true,
		},
		{
			input: `apple co "apples" and ( apple co "mac" or orange ne "foo" ) `,
			want: [][]Filter{
				{
					{
						compare: "co",
						value:   "apples",
					},
				},
				{
					{
						compare: "co",
						value:   "mac",
					},
					{
						compare: "ne",
						value:   "foo",
					},
				},
			},
			ok: true,
		},
		{
			input: `  ( apple co "apples" or apple eq "mac") and ( apple co "mac" or orange ne "foo" ) and test.fruit eq "fruit"   `,
			want: [][]Filter{
				{
					{
						compare: "co",
						value:   "apples",
					},
					{
						compare: "eq",
						value:   "mac",
					},
				},
				{
					{
						compare: "co",
						value:   "mac",
					},
					{
						compare: "ne",
						value:   "foo",
					},
				},
				{
					{
						compare: "eq",
						value:   "fruit",
					},
				},
			},
			ok: true,
		},
		{
			input: `apple eq "A(P)PL(E"`,
			want: [][]Filter{
				{
					{
						compare: "eq",
						value:   "a(p)pl(e",
					},
				},
			},
			ok: false,
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
			if len(f[i]) != len(tc.want[i]) {
				t.Fatalf("BuildFilters(%q, fields) = %+v, want index %d value %+v length %d", tc.input, f[i], i, tc.want[i], len(tc.want[i]))
			}
			for j := 0; j < len(f[i]); j++ {
				if f[i][j].compare != tc.want[i][j].compare {
					t.Fatalf("BuildFilters(%q, fields) = %+v, index %d filter %d compare: want %q, got %q", tc.input, f, i, j, tc.want[i][j].compare, f[i][j].compare)
				}
				if f[i][j].value != tc.want[i][j].value {
					t.Fatalf("BuildFilters(%q, fields) = %+v, index %d filter %d value: want %q, got %q", tc.input, f, i, j, tc.want[i][j].value, f[i][j].value)
				}
			}
		}
		if ok := MatchProtoFilters(f, nil); tc.ok != ok {
			t.Errorf("MatchProtoFilters(%v, nil) = %v, want %v", f, ok, tc.ok)
		}
	}
}

func TestFilters_Errors(t *testing.T) {
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
	tests := []string{
		`bad co "apples"`,
		`apple co "apples`,
		`apple co apples"`,
		`apple zz "apples"`,
		`apple or "apples"`,
		`apple and "apples"`,
		`apple co "apples" and (orange ne "foo"`,
		`( apple co "apples" or orange ne "foo"`,
		`apple co "apples" or apple co "mac" and orange co "foo"`, // requires brackets
		`apple co "apples" OR apple co "mac" and orange co "foo"`, // requires brackets
	}
	for _, tc := range tests {
		f, err := BuildFilters(tc, fields)
		if err == nil {
			t.Fatalf("BuildFilters(%q, fields) = (%v, %v), unexpected success", tc, f, err)
		}
	}
}
