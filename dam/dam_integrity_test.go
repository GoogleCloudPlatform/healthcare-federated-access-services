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

package dam_test

import (
	"context"
	"testing"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/dam"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/storage"

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1"
)

func TestCheckIntegrity(t *testing.T) {
	store := storage.NewMemoryStorage("dam", "testdata/config")
	s := dam.NewService(context.Background(), "test.org", store, nil)
	cfg := &pb.DamConfig{}
	if err := store.Read(storage.ConfigDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, cfg); err != nil {
		t.Fatalf("error reading config: %v", err)
	}
	if err := s.CheckIntegrity(cfg); err != nil {
		t.Errorf("CheckIntegrity(cfg) error: %v", err)
	}
	cfg.Resources["ga4gh-apis"].Views["gcs_read"].Items[0].Vars["bucket"] = "!@@@@"
	if err := s.CheckIntegrity(cfg); err == nil {
		t.Errorf("CheckIntegrity(cfg) on invalid bucket name: expected error, got success")
	}
	cfg.Resources["ga4gh-apis"].Views["gcs_read"].Items[0].Vars["bucket"] = ""
	if err := s.CheckIntegrity(cfg); err != nil {
		t.Errorf("CheckIntegrity(cfg) on empty bucket name: expected success, got error: %v", err)
	}
	cfg.ServiceTemplates["gcs"].Interfaces["http:test"] = "https://example.com/${bad-variable}"
	if err := s.CheckIntegrity(cfg); err == nil {
		t.Errorf("CheckIntegrity(cfg) on bad variable in interface: expected error, got success")
	}
}
