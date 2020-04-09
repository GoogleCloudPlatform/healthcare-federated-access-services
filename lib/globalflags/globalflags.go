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

// Package globalflags contains global flags of binary, eg. Experimental.
package globalflags

import (
	"os"
)

var (
	// Experimental is a global flag determining if experimental features should be enabled.
	// Set from env var: `export FEDERATED_ACCESS_ENABLE_EXPERIMENTAL=true`
	Experimental = os.Getenv("FEDERATED_ACCESS_ENABLE_EXPERIMENTAL") == "true"

	// DisableAuditLog is a global flag determining if you want to disable audit log.
	// Set from env var: `export FEDERATED_ACCESS_DISABLE_AUDIT_LOG=true`
	DisableAuditLog = os.Getenv("FEDERATED_ACCESS_DISABLE_AUDIT_LOG") == "true"

	// EnableDevLog is a global flag determining if you want to enable dev log.
	// Set from env var: `export ENABLE_DEV_LOG=true`
	EnableDevLog = os.Getenv("ENABLE_DEV_LOG") == "true"
)
