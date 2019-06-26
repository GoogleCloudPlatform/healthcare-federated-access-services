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

package adapter_test

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/adapter"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/clouds"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/storage"

	pb "google3/third_party/hcls_federated_access/dam/api/v1/v1"
	ga4gh "github.com/GoogleCloudPlatform/healthcare-federated-access-services"
)

func TestGatekeeperAdapter(t *testing.T) {
	store := storage.NewMemoryStorage("dam-static", "test/config")
	warehouse := clouds.NewMockTokenCreator(false)
	secretStore := storage.NewMemoryStorage("dam", "test/config")
	secrets := &pb.DamSecrets{}
	if err := secretStore.Read("secrets", storage.DefaultRealm, "main", storage.LatestRev, secrets); err != nil {
		t.Fatalf("reading secrets file: %v", err)
	}
	adapters := &adapter.TargetAdapters{
		ByName:      make(map[string]adapter.Adapter),
		Descriptors: make(map[string]*pb.TargetAdapter),
	}
	adapt, err := adapter.NewGatekeeperAdapter(store, warehouse, secrets, adapters)
	if err != nil {
		t.Fatalf("new gatekeeper adapter: %v", err)
	}
	var cfg pb.DamConfig
	cfgStore := storage.NewMemoryStorage("dam", "test/config")
	if err = cfgStore.Read("config", storage.DefaultRealm, "main", storage.LatestRev, &cfg); err != nil {
		t.Fatalf("loading config: %v", err)
	}
	tmpl := "beacon"
	st := cfg.ServiceTemplates[tmpl]
	rname := "ga4gh-apis"
	res := cfg.Resources[rname]
	vname := "beacon"
	view := res.Views[vname]
	err = adapt.CheckConfig(tmpl, st, vname, view, &cfg, adapters)
	if err != nil {
		t.Errorf("CheckConfg(%q, serviceTemplate, %q, view, cfg, adapters): error %v", tmpl, vname, err)
	}

	grantRole := "discovery"
	identity := &ga4gh.Identity{
		Subject: "larry",
	}
	sRole, err := adapter.ResolveServiceRole(grantRole, view, res, &cfg)
	if err != nil {
		t.Fatalf("ResolveServiceRole(%q, view, res, cfg): error %v", grantRole, err)
	}
	r := httptest.NewRequest("GET", "/foo", nil)

	tests := []struct {
		name   string
		input  *adapter.Action
		expect []clouds.MockTokenCreatorEntry
		fail   bool
	}{
		{
			name: "standard beacon token",
			input: &adapter.Action{
				Identity:        identity,
				ClientID:        "client_id",
				Config:          &cfg,
				GrantRole:       grantRole,
				MaxTTL:          168 * time.Hour,
				Request:         r,
				Resource:        res,
				ServiceRole:     sRole,
				ServiceTemplate: st,
				TTL:             60 * time.Second,
				View:            view,
			},
			fail: false,
		},
		{
			name: "too long TTL",
			input: &adapter.Action{
				Identity:        identity,
				ClientID:        "client_id",
				Config:          &cfg,
				GrantRole:       "bad",
				MaxTTL:          1 * time.Hour,
				Request:         r,
				Resource:        res,
				ServiceRole:     sRole,
				ServiceTemplate: st,
				TTL:             400 * time.Hour,
				View:            view,
			},
			fail: true,
		},
	}
	for _, test := range tests {
		_, token, err := adapt.MintToken(test.input)
		if test.fail != (err != nil) {
			t.Fatalf("test %q error mismatch: want error %v, got error %v", test.name, test.fail, err)
		}
		if err == nil && len(token) == 0 {
			t.Errorf("test %q token mismatch: want non-empty, got empty", test.name)
		}
	}
}
