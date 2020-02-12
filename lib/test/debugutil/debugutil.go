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

// Package debugutil provides utilities for debugging.
package debugutil

import (
	"fmt"
	"runtime"

	glog "github.com/golang/glog" /* copybara-comment */
)

// Debug controls debug mode.
var Debug = false

// Logf writes to logs with the stack trace.
func Logf(format string, args ...interface{}) {
	// No-op if not in Debug mode.
	if !Debug {
		return
	}

	// Grab the stack trace for the current goroutine.
	trace := make([]byte, 10000)
	runtime.Stack(trace, false)
	glog.Infof("debugutil.Logf trace:%s\n%v", trace, fmt.Sprintf(format, args...))
}
