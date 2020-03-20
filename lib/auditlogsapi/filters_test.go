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

package auditlogsapi

import (
	"net/url"
	"regexp"
	"testing"
	"time"
)

var (
	fakeTime = time.Date(2020, time.January, 1, 23, 59, 59, 0, time.UTC)
	before   = fakeTime.Add(-time.Hour).Format(time.RFC3339)
	exact    = fakeTime.Format(time.RFC3339)
	after    = fakeTime.Add(time.Hour).Format(time.RFC3339)
)

func TestRFC3999REStr(t *testing.T) {
	tests := []string{
		before,
		exact,
		after,
		time.RFC3339,
	}
	for _, tc := range tests {
		got := regexp.MustCompile(rfc3339REStr).MatchString(tc)
		want := true
		if got != want {
			t.Fatalf("regexp.MustCompile(rfc3339REStr).MatchString(%v) = %v, want %v", fakeTime, got, want)
		}
	}
}

func TestFilterRE(t *testing.T) {
	tests := []struct {
		desc   string
		filter string
		want   bool
	}{
		{
			desc:   "since time",
			filter: "time>=" + before,
			want:   true,
		},
		{
			desc:   "till time",
			filter: "time<=" + after,
			want:   true,
		},
		{
			desc:   "exact time",
			filter: "time=" + exact,
			want:   true,
		},
		{
			desc:   "range time",
			filter: "time>=" + before + " AND " + "time<=" + after,
			want:   true,
		},
	}

	for _, tc := range tests {
		got := timeFilterRE.MatchString(tc.filter)
		if got != tc.want {
			t.Errorf("%v: timeFilterRE.MatchString(%v) = %v, want %v", tc.desc, tc.filter, got, tc.want)
		}
	}
}

func TestExtractFilters(t *testing.T) {
	in := "time>=" + before + " AND " + "time<=" + after
	got, err := extractFilters(in)
	if err != nil {
		t.Fatalf("extractFilters(%v) failed: %v", in, err)
	}
	want := "timestamp>=" + before + " AND " + "timestamp<=" + after
	if got != want {
		t.Fatalf("extractFilters(%v) = %v, want %v", in, got, want)
	}
}

func TestExtractFiltersEscaped(t *testing.T) {
	in := url.QueryEscape("time>=" + before + " AND " + "time<=" + after)
	got, err := extractFilters(in)
	if err != nil {
		t.Fatalf("extractFilters(%v) failed: %v", in, err)
	}
	want := "timestamp>=" + before + " AND " + "timestamp<=" + after
	if got != want {
		t.Fatalf("extractFilters(%v) = %v, want %v", in, got, want)
	}
}
