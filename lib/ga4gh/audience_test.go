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
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
)

func Test_NewAudiance(t *testing.T) {
	tests := []struct {
		desc string
		in   string
		want Audiences
	}{
		{
			desc: "empty",
			in:   "",
			want: nil,
		},
		{
			desc: "non-empty",
			in:   "fake-client",
			want: Audiences{"fake-client"},
		},
	}

	for _, tc := range tests {
		got := NewAudience(tc.in)
		if diff := cmp.Diff(tc.want, got); diff != "" {
			t.Errorf("%v: NewAudience(%v): returned diff (-want +got):\n%s", tc.desc, tc.in, diff)
		}
	}
}

func TestAudiences_UnmarshalJSON(t *testing.T) {
	type withAud struct {
		Audience Audiences `json:"aud,omitempty"`
	}

	tests := []struct {
		desc string
		in   string
		want *withAud
	}{
		{
			desc: "no audience",
			in:   `{}`,
			want: &withAud{},
		},
		{
			desc: "one audience",
			in:   `{"aud":"fake-client"}`,
			want: &withAud{Audiences{"fake-client"}},
		},
		{
			desc: "list zero audience",
			in:   `{"aud":[]}`,
			want: &withAud{},
		},
		{
			desc: "list one audience",
			in:   `{"aud":["fake-client"]}`,
			want: &withAud{Audiences{"fake-client"}},
		},
		{
			desc: "list two audiences",
			in:   `{"aud": ["fake-client-0","fake-client-1"] }`,
			want: &withAud{Audiences{"fake-client-0", "fake-client-1"}},
		},
	}

	for _, tc := range tests {
		got := &withAud{}
		if err := json.Unmarshal([]byte(tc.in), got); err != nil {
			t.Errorf("%v: json.Unmarshal(%v, %T) failed: %v", tc.desc, tc.in, got, err)
		}
		if diff := cmp.Diff(tc.want, got); diff != "" {
			t.Errorf("%v: json.Unmarshal((%v, %T): returned diff (-want +got):\n%s", tc.desc, tc.in, got, diff)
		}
	}
}

func TestAudiences_UnmarshalJSON_BadJSON(t *testing.T) {
	type withAud struct {
		Audience Audiences `json:"aud,omitempty"`
	}

	in := `{aud:[[]]}`
	if err := json.Unmarshal([]byte(in), &withAud{}); err == nil {
		t.Error("json.Unmarshal() should fail when given bad audience JSON")
	}
}
