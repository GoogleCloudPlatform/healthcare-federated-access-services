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

package timeutil

import (
	"testing"
	"time"
)

func TestTimestampString(t *testing.T) {
	epoch := int64(1575344507)
	epochstr := "2019-12-03T03:41:47Z"
	got := TimestampString(epoch)
	if got != epochstr {
		t.Errorf("TimestampString(%d) = %q, want %q", epoch, got, epochstr)
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    time.Duration
		wantErr bool
	}{
		{
			name:    "empty",
			input:   "",
			want:    0,
			wantErr: false,
		},
		{
			name:    "day hour minute second",
			input:   "1d1h1m1s",
			want:    25*time.Hour + time.Minute + time.Second,
			wantErr: false,
		},
		{
			name:    "1 day 100 hour",
			input:   "1d100h",
			want:    124 * time.Hour,
			wantErr: false,
		},
		{
			name:    "float",
			input:   "1.5d1.5h1m1s",
			want:    37*time.Hour + 31*time.Minute + time.Second,
			wantErr: false,
		},
		{
			name:    "- 1 day 100 hour",
			input:   "-1d100h",
			want:    -124 * time.Hour,
			wantErr: false,
		},
		{
			name:    "- 1 minute",
			input:   "-1m",
			want:    -1 * time.Minute,
			wantErr: false,
		},
		{
			name:    "miss order",
			input:   "1s1h1d1m",
			want:    25*time.Hour + time.Minute + time.Second,
			wantErr: false,
		},
		{
			name:    "error",
			input:   "1.1.1d",
			want:    0,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, err := ParseDuration(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("got error %v, want error exists %v", err, tc.wantErr)
			}

			if d != tc.want {
				t.Errorf("result = %s want %s", d.String(), tc.want.String())
			}
		})
	}
}

func TestParseDurationWithDefault_Empty(t *testing.T) {
	defaultDuration := 17 * time.Hour
	input := ""

	d := ParseDurationWithDefault(input, defaultDuration)

	want := defaultDuration
	if d != want {
		t.Errorf("ParseNegDuration(%s, _) = %s want %v", input, d.String(), d.String())
	}
}

func TestParseSeconds(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    time.Duration
		wantErr bool
	}{
		{
			name:    "positive int",
			input:   "1234",
			want:    1234 * time.Second,
			wantErr: false,
		},
		{
			name:    "negative int",
			input:   "-1234",
			want:    -1234 * time.Second,
			wantErr: false,
		},
		{
			name:    "error",
			input:   "12.34",
			want:    0,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, err := ParseSeconds(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("got error %v, want error exists %v", err, tc.wantErr)
			}

			if d != tc.want {
				t.Errorf("ParseSeconds(%s) = %s want %s", tc.input, d.String(), tc.want.String())
			}
		})
	}
}

func TestTTLString(t *testing.T) {
	tests := []struct {
		name  string
		input time.Duration
		want  string
	}{
		{
			name:  "not change",
			input: 1*time.Hour + 1*time.Minute + 1*time.Second,
			want:  "1h1m1s",
		},
		{
			name:  "remove minute second",
			input: 1 * time.Hour,
			want:  "1h",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := TTLString(tc.input)
			if res != tc.want {
				t.Errorf("TTLString(%s) = %s want %s", tc.input, res, tc.want)
			}
		})

	}
}

func TestIsLocale(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "empty input",
			input: "",
			want:  false,
		},
		{
			name:  "simple string",
			input: "en",
			want:  true,
		},
		{
			name:  "locale with country",
			input: "en-ca",
			want:  true,
		},
		{
			name:  "not a locale",
			input: "hello",
			want:  false,
		},
	}

	for _, tc := range tests {
		got := IsLocale(tc.input)
		if got != tc.want {
			t.Errorf("test case %q: IsLocale(%q) = %v, want %v", tc.name, tc.input, got, tc.want)
		}
	}
}

func TestIsTimeZone(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "empty input",
			input: "",
			want:  false,
		},
		{
			name:  "simple string",
			input: "America/Los_Angeles",
			want:  true,
		},
		{
			name:  "not a time zone",
			input: "America/NotaTimeZone",
			want:  false,
		},
	}

	for _, tc := range tests {
		got := IsTimeZone(tc.input)
		if got != tc.want {
			t.Errorf("test case %q: IsTimeZone(%q) = %v, want %v", tc.name, tc.input, got, tc.want)
		}
	}
}
