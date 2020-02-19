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

package common

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	DurationRegexpString = "^([0-9]+d)?([0-9]+h)?([0-9]+m)?([0-9]+s)?$"
)

var (
	dayRE  = regexp.MustCompile(`^(.*[dhms])?([\d\.]+)d(.*)$`)
	hourRE = regexp.MustCompile(`^(.*[dhms])?([\d\.]+)h(.*)$`)
)

// ParseDuration parses the given string to time.Duration. Return the given
// default arg if given string is empty or any error.
// This function supports "d" as days.
func ParseDuration(d string, def time.Duration) (time.Duration, error) {
	if len(d) == 0 {
		return def, nil
	}
	h := float64(0)
	if days := dayRE.FindStringSubmatch(d); len(days) > 3 {
		n, err := strconv.ParseFloat(days[2], 64)
		if err != nil {
			return def, err
		}
		h += n * 24
		d = days[1] + days[3]
	}
	if hours := hourRE.FindStringSubmatch(d); len(hours) > 3 {
		n, err := strconv.ParseFloat(hours[2], 64)
		if err != nil {
			return def, err
		}
		h += n
		d = hours[1] + hours[3]
	}
	if h > 0 {
		d = fmt.Sprintf("%0.3fh%s", h, d)
	}

	out, err := time.ParseDuration(d)
	if err != nil {
		return def, err
	}
	return out, nil
}

// ParseNegDuration parses durations that may sometimes be negative in value.
func ParseNegDuration(d string, def time.Duration) (time.Duration, error) {
	if len(d) == 0 {
		return def, nil
	}
	neg := false
	if d[0] == '-' {
		neg = true
		d = d[1:]
	}
	dur, err := ParseDuration(d, def)
	if err != nil {
		return def, err
	}
	if neg {
		return time.Duration(0) - dur, nil
	}
	return dur, nil
}

// ParseSeconds returns a duration from a numeric string in seconds
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
	if strings.HasSuffix(str, "m0s") {
		str = strings.TrimSuffix(str, "0s")
	}
	if strings.HasSuffix(str, "h0m") {
		str = strings.TrimSuffix(str, "0m")
	}
	if strings.HasSuffix(str, "d0h") {
		str = strings.TrimSuffix(str, "0h")
	}
	return str
}

// TimestampString returns a RFC3339 date/time string.
func TimestampString(epoch int64) string {
	tm := time.Unix(epoch, 0)
	return tm.UTC().Format(time.RFC3339)
}

// PastTimestamp returns a timestamp string a given duration in the past.
func PastTimestamp(ttl time.Duration) string {
	return time.Now().UTC().Add(-1 * ttl).Format(time.RFC3339)
}

// FutureTimestamp returns a timestamp string a given duration in the futhur.
func FutureTimestamp(ttl time.Duration) string {
	return time.Now().UTC().Add(ttl).Format(time.RFC3339)
}

func KeyTTL(maxRequestedTTL time.Duration, numKeys int) time.Duration {
	offset := int(maxRequestedTTL.Seconds()) / numKeys
	return maxRequestedTTL + time.Second*time.Duration(offset+1)
}

// GetNowInUnixNano returns Unix timestamp equivalent to `date "+%s.%N"`.
func GetNowInUnixNano() float64 {
	return float64(time.Now().UnixNano()) / 1e9
}

// GetNowInUnix returns Unix timestamp in seconds, equivalent to `date "+%s"`.
func GetNowInUnix() int64 {
	return time.Now().Unix()
}
