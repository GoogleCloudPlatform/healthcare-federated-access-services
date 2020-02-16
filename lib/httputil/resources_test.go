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

package httputil

import (
	"regexp"
	"testing"
)

func Test_CheckName(t *testing.T) {
	tests := []struct {
		desc    string
		field   string
		name    string
		res     map[string]*regexp.Regexp
		wantErr bool
	}{
		{
			desc:    "empty name",
			field:   "",
			name:    "",
			res:     nil,
			wantErr: true,
		},
		{
			desc:    "match name",
			field:   "user",
			name:    "alice",
			res:     nil,
			wantErr: false,
		},
		{
			desc:    "match long name: realm",
			field:   "realm",
			name:    "master",
			res:     nil,
			wantErr: false,
		},
		{
			desc:    "not match name",
			field:   "user",
			name:    "????",
			res:     nil,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		if err := CheckName(tc.field, tc.name, tc.res); (err != nil) != tc.wantErr {
			t.Errorf("%v: CheckName(%q,%q,%v) = %v, want non-nil err %v", tc.desc, tc.field, tc.name, tc.res, err, tc.wantErr)
		}
	}
}

func Test_IsJSON(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{
			in:   "json",
			want: true,
		},
		{
			in:   "JSON",
			want: true,
		},

		{
			in:   "application/json",
			want: true,
		},

		{
			in:   "html",
			want: false,
		},
	}
	for _, tc := range tests {
		got := IsJSON(tc.in)
		if got != tc.want {
			t.Errorf("IsJSON(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
