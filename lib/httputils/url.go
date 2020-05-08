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
	"net/url"
	"strings"
)

// IsHTTPS checks if the url is using https
func IsHTTPS(in string) bool {
	u, err := url.Parse(in)
	if err != nil {
		return false
	}
	return u.Scheme == "https" && strings.Contains(u.Hostname(), ".")
}

// IsLocalhost checks if the url is hosting in local
func IsLocalhost(in string) bool {
	url, err := url.Parse(in)
	if err != nil {
		return false
	}
	return url.Hostname() == "localhost"
}
