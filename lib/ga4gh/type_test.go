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
	"testing"
)

func Test_ValidType(t *testing.T) {
	tests := []Type{
		AffiliationAndRole,
		AcceptedTermsAndPolicies,
		ResearcherStatus,
		ControlledAccessGrants,
		LinkedIdentities,
		// Example Valid Custom Type from
		// http://bit.ly/ga4gh-passport-v1#custom-passport-visa-types
		Type("https://example.org/passportVisaTypes/researcherStudies"),
	}

	for _, tc := range tests {
		got := ValidType(AffiliationAndRole)
		want := true
		if got != want {
			t.Errorf("ValidType(%v) = %v, want %v", tc, got, want)
		}
	}
}

func Test_ValidType_InvalidCustomType(t *testing.T) {
	typ := Type("example.org/passportVisaTypes/researcherStudies")
	got := ValidType(typ)
	want := false
	if got != want {
		t.Errorf("ValidType(%v) = %v, want %v", typ, got, want)
	}
}

func Test_CustomType(t *testing.T) {
	typ := Type("https://example.org/passportVisaTypes/researcherStudies")
	got := CustomType(typ)
	want := true
	if got != want {
		t.Errorf("CustomType(%v) = %v, want %v", typ, got, want)
	}
}

func Test_CustomType_InvalidCustomType(t *testing.T) {
	typ := Type("example.org/invalid-no-schema")
	got := CustomType(typ)
	want := false
	if got != want {
		t.Errorf("CustomType(%v) = %v, want %v", typ, got, want)
	}
}

func Test_MatchPatterns(t *testing.T) {
	tests := []struct {
		desc    string
		pattern Pattern
		value   string
		match   bool
	}{
		{
			desc:    "no pattern match",
			pattern: "",
			value:   "",
			match:   true,
		},
		{
			desc:    "unkown pattern no-match",
			pattern: "zzz:",
			value:   "",
			match:   false,
		},
		{
			desc:    "const pattern match",
			pattern: "const:foo",
			value:   "foo",
			match:   true,
		},
		{
			desc:    "const pattern no-match",
			pattern: "const:foo",
			value:   "bar",
			match:   false,
		},
		{
			desc:    "pattern * match",
			pattern: "pattern:*",
			value:   "foo",
			match:   true,
		},
		{
			desc:    "pattern ? match",
			pattern: "pattern:?oo",
			value:   "foo",
			match:   true,
		},
		{
			desc:    "pattern general match",
			pattern: "pattern:foo*foo???",
			value:   "foobarfoobar",
			match:   true,
		},
		{
			desc:    "pattern no-match",
			pattern: "pattern:*foo*",
			value:   "bar",
			match:   false,
		},
		{
			desc:    "split_pattern match",
			pattern: "split_pattern:foo*foo;bar*bar",
			value:   "foobarfoo",
			match:   true,
		},
		{
			desc:    "split_pattern match",
			pattern: "split_pattern:foo*foo;bar*bar",
			value:   "barfoobar",
			match:   true,
		},
		{
			desc:    "split_pattern no-match",
			pattern: "split_pattern:foo*foo;bar*bar",
			value:   "baz",
			match:   false,
		},
	}

	for _, tc := range tests {
		if err := MatchPatterns(tc.pattern, tc.value); (err == nil) != tc.match {
			t.Errorf("%v: MatchPatterns(%q,%q) = %v, want nil error %v", tc.desc, tc.pattern, tc.value, err, tc.match)
		}
	}
}

func Test_MatchRegExp(t *testing.T) {
	tests := []struct {
		r    RegExp
		v    Value
		want bool
	}{
		{
			r:    "foo(0|1)*bar",
			v:    "foo10101010bar",
			want: true,
		},
		{
			r:    "foo(0|1)*bar",
			v:    "bar01010101bar",
			want: false,
		},
		{
			r:    "][",
			v:    "",
			want: false,
		},
	}

	for _, tc := range tests {
		got := MatchRegExp(tc.r, tc.v)
		if got != tc.want {
			t.Errorf("MatchRegExp(%q,%q) = %v, want %v", tc.r, tc.v, got, tc.want)
		}
	}
}
