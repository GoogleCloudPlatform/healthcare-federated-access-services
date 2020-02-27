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
	"context"
	"testing"
	"time"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/adapter" /* copybara-comment: adapter */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds" /* copybara-comment: clouds */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
)

func TestGatekeeperAdapter(t *testing.T) {
	store := storage.NewMemoryStorage("dam-static", "testdata/config")
	warehouse := clouds.NewMockTokenCreator(false)
	secretStore := storage.NewMemoryStorage("dam", "testdata/config")
	secrets := &pb.DamSecrets{}
	if err := secretStore.Read(storage.SecretsDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, secrets); err != nil {
		t.Fatalf("reading secrets file: %v", err)
	}
	adapters := &adapter.ServiceAdapters{
		ByAdapterName: make(map[string]adapter.ServiceAdapter),
		ByServiceName: make(map[string]adapter.ServiceAdapter),
		Descriptors:   make(map[string]*pb.ServiceDescriptor),
	}
	adapt, err := adapter.NewGatekeeperAdapter(store, warehouse, secrets, adapters)
	if err != nil {
		t.Fatalf("new gatekeeper adapter: %v", err)
	}
	var cfg pb.DamConfig
	cfgStore := storage.NewMemoryStorage("dam", "testdata/config")
	if err = cfgStore.Read(storage.ConfigDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, &cfg); err != nil {
		t.Fatalf("loading config: %v", err)
	}
	tmpl := "beacon"
	st := cfg.ServiceTemplates[tmpl]
	rname := "ga4gh-apis"
	res := cfg.Resources[rname]
	vname := "beacon"
	view := res.Views[vname]
	_, err = adapt.CheckConfig(tmpl, st, rname, vname, view, &cfg, adapters)
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
		result, err := adapt.MintToken(context.Background(), test.input)
		if test.fail != (err != nil) {
			t.Fatalf("test %q error mismatch: want error %v, got error %v", test.name, test.fail, err)
		}
		if err == nil && (len(result.Credentials) == 0 || len(result.Credentials["access_token"]) == 0) {
			t.Errorf("test %q token mismatch: want non-empty, got empty", test.name)
		}
	}
}
