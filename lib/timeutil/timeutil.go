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

// Package timeutil provides utilities for working with time related objects.
package timeutil

import (
	"time"

	"github.com/golang/protobuf/ptypes" /* copybara-comment */

	dpb "github.com/golang/protobuf/ptypes/duration" /* copybara-comment */
	tspb "github.com/golang/protobuf/ptypes/timestamp" /* copybara-comment */
)

// RFC3339 convers a Timestamp to RFC3339 string.
// Returns "" if the timestamp is invalid.
func RFC3339(ts *tspb.Timestamp) string {
	t, err := ptypes.Timestamp(ts)
	if err != nil {
		return ""
	}
	return t.Format(time.RFC3339)
}

// TimestampProto returns the timestamp proto for a given time.
// Returns empty if the time is invalid.
func TimestampProto(t time.Time) *tspb.Timestamp {
	ts, err := ptypes.TimestampProto(t)
	if err != nil {
		return &tspb.Timestamp{}
	}
	return ts
}

// Time returns the time for a given timestamp.
// Returns 0 if the timestamp is invalid.
func Time(ts *tspb.Timestamp) time.Time {
	t, err := ptypes.Timestamp(ts)
	if err != nil {
		return time.Time{}
	}
	return t
}

// DurationProto returns the duration proto for a given duration.
func DurationProto(d time.Duration) *dpb.Duration {
	return ptypes.DurationProto(d)
}

// Duration returns the time for a given timestamp.
// Returns 0 if the timestamp is invalid.
func Duration(ds *dpb.Duration) time.Duration {
	d, err := ptypes.Duration(ds)
	if err != nil {
		return 0
	}
	return d
}
