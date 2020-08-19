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

package optional

import (
	"testing"
	"time"
)

func TestNewIntFromString(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantPresent bool
		wantError   bool
		wantValue   int
	}{
		{
			name:        "default",
			input:       "1",
			wantPresent: true,
			wantError:   false,
			wantValue:   1,
		},
		{
			name:        "empty",
			input:       "",
			wantPresent: false,
			wantError:   false,
		},
		{
			name:      "error",
			input:     "a",
			wantError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NewIntFromString(tc.input)
			if tc.wantError {
				if err == nil {
					t.Errorf("NewIntFromString(%q) wants err", tc.input)
				}
				return
			}

			if err != nil {
				t.Fatalf("NewIntFromString(%q) failed: %v", tc.input, err)
			}

			if got.IsPresent() != tc.wantPresent {
				t.Errorf("IsPresent() = %v wants %v", got.IsPresent(), tc.wantPresent)
			}

			if got.IsPresent() && (got.Get() != tc.wantValue) {
				t.Errorf("Get() = %v wants %v", got.Get(), tc.wantValue)
			}
		})
	}
}

func TestNewDurationFromString(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantPresent bool
		wantError   bool
		wantValue   time.Duration
	}{
		{
			name:        "default",
			input:       "1h",
			wantPresent: true,
			wantError:   false,
			wantValue:   time.Hour,
		},
		{
			name:        "empty",
			input:       "",
			wantPresent: false,
			wantError:   false,
		},
		{
			name:      "error",
			input:     "a",
			wantError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NewDurationFromString(tc.input)
			if tc.wantError {
				if err == nil {
					t.Errorf("NewDurationFromString(%q) wants err", tc.input)
				}
				return
			}

			if err != nil {
				t.Fatalf("NewDurationFromString(%q) failed: %v", tc.input, err)
			}

			if got.IsPresent() != tc.wantPresent {
				t.Errorf("IsPresent() = %v wants %v", got.IsPresent(), tc.wantPresent)
			}

			if got.IsPresent() && (got.Get() != tc.wantValue) {
				t.Errorf("Get() = %v wants %v", got.Get(), tc.wantValue)
			}
		})
	}
}
