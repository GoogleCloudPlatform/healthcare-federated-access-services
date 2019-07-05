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
