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

// Package optional provides container objects which may or may not contain a non-null value.
package optional

import (
	"fmt"
	"strconv"
	"time"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/timeutil" /* copybara-comment: timeutil */
)

// Int in a container objects which may or may not contain an int.
type Int struct {
	present bool
	value   int
}

// NewInt creates optional.Int from int.
func NewInt(i int) *Int {
	return &Int{present: true, value: i}
}

// NewIntFromString creates optional.Int from string.
func NewIntFromString(s string) (*Int, error) {
	if len(s) == 0 {
		return &Int{}, nil
	}

	v, err := strconv.ParseInt(s, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("ParseInt(%q) failed: %v", s, err)
	}

	return NewInt(int(v)), nil
}

// IsPresent returns if the object contains an int.
func (s *Int) IsPresent() bool {
	return s.present
}

// Get returns the value in the contains.
func (s *Int) Get() int {
	return s.value
}

// Duration in a container objects which may or may not contain an Duration.
type Duration struct {
	present bool
	value   time.Duration
}

// NewDuration creates optional.Duration from Duration.
func NewDuration(s time.Duration) *Duration {
	return &Duration{present: true, value: s}
}

// NewDurationFromString creates optional.Duration from string.
func NewDurationFromString(s string) (*Duration, error) {
	if len(s) == 0 {
		return &Duration{}, nil
	}

	d, err := timeutil.ParseDuration(s)
	if err != nil {
		return nil, fmt.Errorf("timeutil.ParseDuration(%q) failed: %v", s, err)
	}

	return NewDuration(d), nil
}

// IsPresent returns if the object contains an Duration.
func (s *Duration) IsPresent() bool {
	return s.present
}

// Get returns the value in the contains.
func (s *Duration) Get() time.Duration {
	return s.value
}
