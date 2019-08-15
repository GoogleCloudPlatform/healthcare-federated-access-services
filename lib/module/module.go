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

// Package module provides optional, extended functionality.
package module

import (
	dampb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1"
)

// Module offers extended functionality that can be added or removed from
// various environments.
type Module interface {
	// ModuleName returns a named identifier for this module.
	ModuleName() string
	// LoadPersonas allows and IC to load personas from a DAM.
	LoadPersonas(realm string) (map[string]*dampb.TestPersona, error)
}
