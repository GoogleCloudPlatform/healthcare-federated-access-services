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

// Package osenv provides utilities to read flag-like enviroment variables.
package osenv

import (
	"os"

	glog "github.com/golang/glog" /* copybara-comment */
)

var (
	osGetEnv  = os.Getenv
	glogExitf = glog.Exitf
)

// MustVar reads the value of an environment string variable.
// if it is not set, exits.
func MustVar(key string) string {
	v := osGetEnv(key)
	if v == "" {
		glogExitf("Environment variable %q is not set.", key)
	}
	return v
}

// VarWithDefault reads the value of an environment string variable.
// if it is not set, returns the provided default value.
func VarWithDefault(key string, d string) string {
	v := osGetEnv(key)
	if v == "" {
		return d
	}
	return v
}
