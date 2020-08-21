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

package httputils

import (
	"net/http"
	"sort"
	"strings"

	"bitbucket.org/creachadair/stringset" /* copybara-comment */
)

// CSP handles Content Security Policy headers.
// See https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
type CSP struct {
	data map[string]*stringset.Set
}

// CSPFromString reads csp from header.
func CSPFromString(str string) *CSP {
	c := &CSP{data: map[string]*stringset.Set{}}

	for _, s := range strings.Split(str, ";") {
		trimed := strings.TrimSpace(s)
		ss := strings.Split(trimed, " ")
		if len(ss) < 2 {
			continue
		}

		name := ss[0]
		for _, value := range ss[1:] {
			c.add(name, value)
		}
	}

	return c
}

func mergeCSP(a, b *CSP) *CSP {
	if a == nil || len(a.data) == 0 {
		return b
	}

	if b == nil || len(b.data) == 0 {
		return a
	}

	c := &CSP{data: map[string]*stringset.Set{}}

	for name, values := range a.data {
		for _, v := range values.Unordered() {
			c.add(name, v)
		}
	}

	for name, values := range b.data {
		for _, v := range values.Unordered() {
			c.add(name, v)
		}
	}

	return c
}

// add given name, value to CSP
func (s *CSP) add(name, value string) {
	if len(name) == 0 || len(value) == 0 {
		return
	}
	if _, ok := s.data[name]; !ok {
		s.data[name] = &stringset.Set{}
	}
	s.data[name].Add(value)
}

func (s *CSP) addToHeader(w http.ResponseWriter) {
	var list []string

	// 1. each policy format as: name value1 value2
	for name, values := range s.data {
		vs := []string{name}
		vs = append(vs, values.Elements()...)
		list = append(list, strings.Join(vs, " "))
	}

	sort.Strings(list)

	// 2. policies separated by ";"
	v := strings.Join(list, ";")

	w.Header().Set("Content-Security-Policy", v)
}

var (
	// pageCSP : for page, we should only allow item we know.
	pageCSP = CSPFromString(
		// fallback policy
		"default-src 'self';" +
			// ajax.googleapis.com only includes small number of libs. https://developers.google.com/speed/libraries
			// code.getmdl.io for Material Design Lite style
			"script-src 'self' https://ajax.googleapis.com https://code.getmdl.io;" +
			// fonts.googleapis.com for fonts
			// code.getmdl.io for Material Design Lite style
			"style-src 'self' https://fonts.googleapis.com https://code.getmdl.io;" +
			// fonts.gstatic.com for fonts
			"font-src https://fonts.gstatic.com;" +
			// data: for Material Design Lite style icon inline css
			"img-src 'self' data:;" +
			// allow frame hosted on same host to contain this page
			"frame-ancestors 'self'",
	)
)
