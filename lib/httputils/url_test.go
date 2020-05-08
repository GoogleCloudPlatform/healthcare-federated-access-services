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

import "testing"

func TestIsHTTPS(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{
			name: "https",
			url:  "https://example.com",
			want: true,
		},
		{
			name: "no https",
			url:  "http://example.com",
			want: false,
		},
		{
			name: "no public domain",
			url:  "https://example-com",
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsHTTPS(tc.url)
			if got != tc.want {
				t.Errorf("IsHTTPS(%s) wants %v", tc.url, tc.want)
			}
		})
	}
}

func TestIsLocalhost(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{
			name: "localhost with path, https and post",
			url:  "https://localhost:12345/path",
			want: true,
		},
		{
			name: "dot localhost",
			url:  "http://example.localhost",
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsLocalhost(tc.url)
			if got != tc.want {
				t.Errorf("IsLocalhost(%s) wants %v", tc.url, tc.want)
			}
		})
	}
}
