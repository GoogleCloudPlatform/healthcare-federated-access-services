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
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/golang/protobuf/ptypes" /* copybara-comment */
	"golang.org/x/text/language" /* copybara-comment */

	dpb "github.com/golang/protobuf/ptypes/duration" /* copybara-comment */
	tspb "github.com/golang/protobuf/ptypes/timestamp" /* copybara-comment */
)

const (
	// DurationREStr is a regexp for a duration string consiting of
	// days, hours, minutess, and seconds (each one is optional).
	DurationREStr = "^([0-9]+d)?([0-9]+h)?([0-9]+m)?([0-9]+s)?$"
)

var (
	dayRE  = regexp.MustCompile(`^(.*[dhms])?([\d\.]+)d(.*)$`)
	hourRE = regexp.MustCompile(`^(.*[dhms])?([\d\.]+)h(.*)$`)
)

// ParseDuration parses the given duration string to time.Duration.
// It supports "d" for days which time.ParseDuration does not.
// Each day is 24 hours.
func ParseDuration(d string) (time.Duration, error) {
	if len(d) == 0 {
		return 0, nil
	}
	neg := time.Duration(1)
	if d[0] == '-' {
		neg = -1
		d = d[1:]
	}

	h := float64(0)
	if days := dayRE.FindStringSubmatch(d); len(days) > 3 {
		n, err := strconv.ParseFloat(days[2], 64)
		if err != nil {
			return 0, err
		}
		h += n * 24
		d = days[1] + days[3]
	}

	if hours := hourRE.FindStringSubmatch(d); len(hours) > 3 {
		n, err := strconv.ParseFloat(hours[2], 64)
		if err != nil {
			return 0, err
		}
		h += n
		d = hours[1] + hours[3]
	}
	if h > 0 {
		d = fmt.Sprintf("%0.3fh%s", h, d)
	}

	out, err := time.ParseDuration(d)
	if err != nil {
		return 0, err
	}

	return neg * out, nil
}

// ParseDurationWithDefault parses the given duration string.
// Returns the provided default if the string is empty or on error.
func ParseDurationWithDefault(d string, def time.Duration) time.Duration {
	if len(d) == 0 {
		return def
	}
	v, err := ParseDuration(d)
	if err != nil {
		return def
	}
	return v
}

// ParseSeconds returns a duration from a numeric string in seconds.
func ParseSeconds(d string) (time.Duration, error) {
	n, err := strconv.ParseInt(d, 10, 64)
	if err != nil {
		return 0, err
	}
	return time.Duration(n) * time.Second, nil
}

// TTLString removes tailing 0s, 0m, 0h for human readable.
func TTLString(ttl time.Duration) string {
	str := ttl.String()
	str = strings.TrimSuffix(str, "0s")
	str = strings.TrimSuffix(str, "0m")
	str = strings.TrimSuffix(str, "0h")
	return str
}

// KeyTTL retuns the ttl for a number of keys.
func KeyTTL(maxRequestedTTL time.Duration, numKeys int) time.Duration {
	offset := int(maxRequestedTTL.Seconds()) / numKeys
	return maxRequestedTTL + time.Second*time.Duration(offset+1)
}

// IsTimeZone returns true if the "name" provided is an IANA Time Zone name.
func IsTimeZone(name string) bool {
	if name == "" {
		return false
	}
	if _, err := time.LoadLocation(name); err != nil {
		return false
	}
	return true
}

// IsLocale returns true if the "name" provided is a locale name as per
// https://tools.ietf.org/html/bcp47.
func IsLocale(name string) bool {
	if _, err := language.Parse(name); err != nil {
		return false
	}
	return true
}

// TimestampString returns a RFC3339 date/time string for seconds sinc epoch.
func TimestampString(secs int64) string {
	return time.Unix(secs, 0).UTC().Format(time.RFC3339)
}

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
