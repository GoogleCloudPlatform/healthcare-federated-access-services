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

// Package jsonutil contains helpers for working with JSON.
package jsonutil

import (
	"bytes"
	"encoding/json"
	"fmt"

	glog "github.com/golang/glog"
)

const indent = "  "

// Canonical return a canonical formatted version of a JSON text.
func Canonical(j string) (string, error) {
	var s interface{}
	if err := json.Unmarshal([]byte(j), &s); err != nil {
		return "", fmt.Errorf("json.Unmarshal(%q) failed: %v", j, err)
	}
	d, err := json.Marshal(&s)
	if err != nil {
		return "", fmt.Errorf("json.Marshal(%q) failed: %v", s, err)
	}
	c := &bytes.Buffer{}
	if err := json.Indent(c, d, "", indent); err != nil {
		return "", fmt.Errorf("json.Indent(%v,%v,%v,%v) failed: %v", c, d, "", indent, err)
	}
	return c.String(), nil
}

// MustCanonical is a test wrapper around Canonical.
// DO NOT USE IN PROD CODE.
// Crashes if any errors occurs.
func MustCanonical(j string) string {
	glog.Infof("Transforming to Canonical JSON: %q", j)
	res, err := Canonical(j)
	if err != nil {
		glog.Fatalf("MustCanonical(%q) failed: %v", j, err)
	}
	return res
}
