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
	"testing"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/storage"

	dampb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/dam/api/v1"
)

// TestModule provides extended functionality for testing infrastructure.
type TestModule struct {
	store storage.StorageInterface
	realm string
	cfg   *dampb.DamConfig
}

// NewTestModule creates a module for testing infrastructure.
func NewTestModule(t *testing.T, store storage.StorageInterface, realm string) Module {
	cfg := &dampb.DamConfig{}
	if err := store.Read("config", realm, "main", storage.LatestRev, cfg); err != nil {
		t.Fatalf("loading config: %v", err)
	}
	return &TestModule{
		store: store,
		realm: realm,
		cfg:   cfg,
	}
}

// ModuleName returns a named identifier for this module.
func (m *TestModule) ModuleName() string {
	return "test"
}

// LoadPersonas allows and IC to load personas from a DAM.
func (m *TestModule) LoadPersonas(realm string) (map[string]*dampb.TestPersona, error) {
	return m.cfg.TestPersonas, nil
}
