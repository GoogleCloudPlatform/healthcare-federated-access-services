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

// Package serviceinfo stores service runtime info.
package serviceinfo

var (
	// Project the GCP project that the service is running in.
	Project = "unknown"
	// Type ic, dam, persona, to identity the binary.
	Type = "unknown"
	// Name the GAE runtime service name, to identity the service.
	Name = "unknown"
)
