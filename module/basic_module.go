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

package module

import (
	dampb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/dam/api/v1"
)

// Basic provides no extended functionality.
type Basic struct {
}

// NewBasicModule creates a module with no extended functionality.
func NewBasicModule() Module {
	return &Basic{}
}

// ModuleName returns a named identifier for this module.
func (m *Basic) ModuleName() string {
	return "basic"
}

// LoadPersonas allows and IC to load personas from a DAM.
func (m *Basic) LoadPersonas(realm string) (map[string]*dampb.TestPersona, error) {
	return make(map[string]*dampb.TestPersona), nil
}
