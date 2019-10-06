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
	"net/http"
	"strings"
	"unicode"

	"github.com/pborman/uuid"
)

const (
	RealmVariable = "{realm}"
)

func ListContains(list []string, find string) bool {
	for _, entry := range list {
		if entry == find {
			return true
		}
	}
	return false
}

func RequestAbstractPath(r *http.Request) string {
	parts := strings.Split(r.URL.Path, "/")
	// Path starts with a "/", so first part is always empty.
	if len(parts) > 3 {
		parts[3] = RealmVariable
	}
	return strings.Join(parts, "/")
}

func GenerateGUID() string {
	return uuid.New()
}

func ParseGUID(in string) (uuid.UUID, error) {
	return uuid.Parse(in), nil
}

// JoinNonEmpty filters empty strings and joins remainder together.
func JoinNonEmpty(in []string, separator string) string {
	out := []string{}
	for _, v := range in {
		if len(v) > 0 {
			out = append(out, v)
		}
	}
	return strings.Join(out, separator)
}

// FilterStringsByPrefix filters returns only strings that do NOT have a given prefix.
func FilterStringsByPrefix(in []string, prefix string) []string {
	var out []string
	for _, v := range in {
		if !strings.HasPrefix(v, prefix) {
			out = append(out, v)
		}
	}
	return out
}

// ToTitle does some auto-formatting on camel-cased or snake-cased strings to make them look like titles.
func ToTitle(str string) string {
	out := ""
	l := 0
	for i, ch := range str {
		if unicode.IsUpper(ch) && i > 0 && str[i-1] != ' ' {
			out += " "
			l++
		} else if ch == '_' {
			out += " "
			l++
			continue
		}
		if l > 0 && out[l-1] == ' ' {
			ch = rune(unicode.ToUpper(rune(ch)))
		}
		out += string(ch)
		l++
	}
	return strings.Title(out)
}
