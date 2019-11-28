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

	"github.com/golang/protobuf/proto"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/dam"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage"

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1"
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1"
)

const (
	hydraAdminURL = "https://admin.hydra.example.com"
	notUseHydra   = false
)

func TestCheckIntegrity(t *testing.T) {
	store := storage.NewMemoryStorage("dam", "testdata/config")
	s := dam.NewService(context.Background(), "test.org", "no-broker", hydraAdminURL, store, nil, notUseHydra)
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
	badcfg := &pb.DamConfig{}
	proto.Merge(badcfg, cfg)
	badcfg.ServiceTemplates["gcs"].Interfaces["http:test"] = "https://example.com/${bad-variable}"
	if err := s.CheckIntegrity(badcfg); err == nil {
		t.Errorf("CheckIntegrity(badcfg) on bad variable in interface: expected error, got success")
	}
	badcfg.Reset()
	proto.Merge(badcfg, cfg)
	assert := badcfg.TestPersonas["dr_joe_era_commons"].Passport.Ga4GhAssertions[1].AnyOfConditions[0]
	assert.AllOf = append(assert.AllOf, &cpb.Condition{})
	if err := s.CheckIntegrity(badcfg); err == nil {
		t.Errorf("CheckIntegrity(badcfg) on empty condition: expected error, got success")
	}
}
