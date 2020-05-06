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

// Package muxtest contains test helpers for testing endpoints client credentials requirement.
package muxtest

import (
	"sort"
	"strings"
	"testing"

	"github.com/gorilla/mux" /* copybara-comment */
	"bitbucket.org/creachadair/stringset" /* copybara-comment */
)

// PathsInRouter returns paths in router.
func PathsInRouter(t *testing.T, r *mux.Router) stringset.Set {
	t.Helper()

	paths := stringset.New()

	r.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		path, err := route.GetPathTemplate()
		if err != nil {
			t.Fatalf("GetPathTemplate() failed: %v", err)
		}
		methods, err := route.GetMethods()
		if err != nil {
			// route does not have methods
			paths.Add(path)
			return nil
		}
		sort.Strings(methods)

		m := strings.Join(methods, "|")
		paths.Add(m + " " + path)

		return nil
	})

	return paths
}
