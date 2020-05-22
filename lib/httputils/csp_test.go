// Copyright 2020 Google LLC.
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

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"bitbucket.org/creachadair/stringset" /* copybara-comment */
)

func TestCSPVars(t *testing.T) {
	t.Run("pageCSP", func(t *testing.T) {
		want := &CSP{
			data: map[string]*stringset.Set{
				"default-src": &stringset.Set{
					"'self'": struct{}{},
				},
				"frame-ancestors": &stringset.Set{
					"'self'": struct{}{},
				},
				"font-src": &stringset.Set{
					"https://fonts.gstatic.com": struct{}{},
				},
				"img-src": &stringset.Set{
					"'self'":                  struct{}{},
					"data:":                   struct{}{},
					"http://icon-library.com": struct{}{},
				},
				"script-src": &stringset.Set{
					"'self'":                      struct{}{},
					"https://ajax.googleapis.com": struct{}{},
					"https://code.getmdl.io":      struct{}{},
				},
				"style-src": &stringset.Set{
					"'self'":                       struct{}{},
					"https://code.getmdl.io":       struct{}{},
					"https://fonts.googleapis.com": struct{}{},
				},
			},
		}

		if d := cmp.Diff(want, pageCSP, cmp.AllowUnexported(CSP{})); len(d) > 0 {
			t.Errorf("pageCSP (-want, +got): %s", d)
		}
	})
}

func TestCSPFromString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  *CSP
	}{
		{
			name:  "empty",
			input: "",
			want:  &CSP{data: map[string]*stringset.Set{}},
		},
		{
			name:  "policy without value",
			input: "a",
			want:  &CSP{data: map[string]*stringset.Set{}},
		},
		{
			name:  "empty policy",
			input: "a b;",
			want: &CSP{data: map[string]*stringset.Set{
				"a": &stringset.Set{
					"b": struct{}{},
				},
			}},
		},
		{
			name:  "spaces in policy",
			input: "a  b ;",
			want: &CSP{data: map[string]*stringset.Set{
				"a": &stringset.Set{
					"b": struct{}{},
				},
			}},
		},
		{
			name:  "duplicated in policy",
			input: "a b;a b b",
			want: &CSP{data: map[string]*stringset.Set{
				"a": &stringset.Set{
					"b": struct{}{},
				},
			}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CSPFromString(tc.input)
			if d := cmp.Diff(tc.want, got, cmp.AllowUnexported(CSP{})); len(d) > 0 {
				t.Errorf("CSPFromString (-want, +got): %s", d)
			}
		})
	}
}

func Test_mergeCSP(t *testing.T) {
	tests := []struct {
		name string
		a    *CSP
		b    *CSP
		want *CSP
	}{
		{
			name: "a nil",
			a:    nil,
			b:    CSPFromString("a b"),
			want: CSPFromString("a b"),
		},
		{
			name: "b nil",
			a:    CSPFromString("a b"),
			b:    nil,
			want: CSPFromString("a b"),
		},
		{
			name: "a empty",
			a:    CSPFromString(""),
			b:    CSPFromString("a b"),
			want: CSPFromString("a b"),
		},
		{
			name: "b empty",
			a:    CSPFromString("a b"),
			b:    CSPFromString(""),
			want: CSPFromString("a b"),
		},
		{
			name: "duplicated",
			a:    CSPFromString("a b"),
			b:    CSPFromString("a b"),
			want: CSPFromString("a b"),
		},
		{
			name: "merge",
			a:    CSPFromString("a b c;d e"),
			b:    CSPFromString("a b"),
			want: CSPFromString("a b c;d e"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mergeCSP(tc.a, tc.b)
			if d := cmp.Diff(tc.want, got, cmp.AllowUnexported(CSP{})); len(d) > 0 {
				t.Errorf("mergeCSP (-want, +got): %s", d)
			}
		})
	}
}

func Test_CSP_addToHeader(t *testing.T) {
	c := CSPFromString("a a1 a2;b b1 b2")
	w := httptest.NewRecorder()
	c.addToHeader(w)
	got := w.Header()

	want := http.Header{}
	want.Set("Content-Security-Policy", "a a1 a2;b b1 b2")

	if d := cmp.Diff(want, got); len(d) > 0 {
		t.Errorf("header (-want, +got): %s", d)
	}
}
