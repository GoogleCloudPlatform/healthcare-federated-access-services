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

	pb "google3/third_party/hcls_federated_access/dam/api/v1/v1"
)

func TestCheckIntegrity(t *testing.T) {
	store := storage.NewMemoryStorage("dam", "test/config")
	s := dam.NewService(context.Background(), "test.org", store, nil)
	cfg := &pb.DamConfig{}
	if err := store.Read("config", storage.DefaultRealm, "main", storage.LatestRev, cfg); err != nil {
		t.Fatalf("error reading config: %v", err)
	}
	if err := s.CheckIntegrity(cfg); err != nil {
		t.Errorf("CheckIntegrity(cfg) error: %v", err)
	}
}
