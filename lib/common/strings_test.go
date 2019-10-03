/*
 * Copyright 2019 Google LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package common

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestJoinNonEmpty(t *testing.T) {
	tests := []struct {
		Name      string
		Input     []string
		Separator string
		Expect    string
	}{
		{
			Name:   "empty input",
			Input:  []string{},
			Expect: "",
		},
		{
			Name:   "one string",
			Input:  []string{"one"},
			Expect: "one",
		},
		{
			Name:   "two strings",
			Input:  []string{"one", "two"},
			Expect: "one two",
		},
		{
			Name:      "non-space multi-character separator",
			Input:     []string{"one", "two"},
			Separator: "@@@",
			Expect:    "one@@@two",
		},
		{
			Name:   "empty strings",
			Input:  []string{"", "one", "", "", "two", "", "three", ""},
			Expect: "one two three",
		},
	}

	for _, test := range tests {
		sep := " "
		if len(test.Separator) > 0 {
			sep = test.Separator
		}
		got := JoinNonEmpty(test.Input, sep)
		if got != test.Expect {
			t.Errorf("test %q: want %q, got %q", test.Name, test.Expect, got)
		}
	}
}

func TestRemoveStringsByPrefix(t *testing.T) {
	tests := []struct {
		name   string
		input  []string
		prefix string
		expect []string
	}{
		{
			name:   "nil input",
			input:  nil,
			expect: nil,
		},
		{
			name:   "empty input",
			input:  []string{},
			expect: nil,
		},
		{
			name:   "one string no match",
			input:  []string{"one"},
			prefix: "foo",
			expect: []string{"one"},
		},
		{
			name:   "one string match",
			input:  []string{"one"},
			prefix: "o",
			expect: nil,
		},
		{
			name:   "two strings remove first",
			input:  []string{"one", "two"},
			prefix: "one",
			expect: []string{"two"},
		},
		{
			name:   "two strings remove second",
			input:  []string{"one", "two"},
			prefix: "two",
			expect: []string{"one"},
		},
		{
			name:   "remove all",
			input:  []string{"none", "nothing"},
			prefix: "no",
			expect: nil,
		},
		{
			name:   "empty strings",
			input:  []string{"", "one", "", "", "two", "", "three", ""},
			prefix: "t",
			expect: []string{"", "one", "", "", "", ""},
		},
		{
			name:   "paths",
			input:  []string{"aaa/bbbb/ccc", "aaa/bbb/ccc", "zzz", "aaa/bbb"},
			prefix: "aaa/bbb/",
			expect: []string{"aaa/bbbb/ccc", "zzz", "aaa/bbb"},
		},
	}

	for _, tc := range tests {
		got := FilterStringsByPrefix(tc.input, tc.prefix)
		if diff := cmp.Diff(got, tc.expect); diff != "" {
			t.Errorf("test case %q: FilterStringsByPrefix(%v, %q) returned diff (-want +got):\n%s", tc.name, tc.input, tc.prefix, diff)
		}
	}
}
