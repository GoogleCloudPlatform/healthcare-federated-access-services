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
	"reflect"
	"testing"
	"time"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/adapter"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/clouds"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/storage"

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/dam/api/v1"
	ga4gh "github.com/GoogleCloudPlatform/healthcare-federated-access-services"
)

func TestAggregatorAdapter(t *testing.T) {
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
	sawAdapt, err := adapter.NewSawAdapter(store, warehouse, secrets, adapters)
	if err != nil {
		t.Fatalf("error creating SAW adapter: %v", err)
	}
	adapters.ByName[sawAdapt.Name()] = sawAdapt
	adapters.Descriptors[sawAdapt.Name()] = sawAdapt.Descriptor()

	adapt, err := adapter.NewAggregatorAdapter(store, warehouse, secrets, adapters)
	if err != nil {
		t.Fatalf("new aggregator adapter: %v", err)
	}
	adapters.ByName[adapt.Name()] = adapt
	adapters.Descriptors[adapt.Name()] = adapt.Descriptor()
	var cfg pb.DamConfig
	cfgStore := storage.NewMemoryStorage("dam", "test/config")
	if err = cfgStore.Read("config", storage.DefaultRealm, "main", storage.LatestRev, &cfg); err != nil {
		t.Fatalf("loading config: %v", err)
	}
	tmpl := "views"
	st := cfg.ServiceTemplates[tmpl]
	rname := "dataset_example"
	res := cfg.Resources[rname]
	vname := "gcp"
	view := res.Views[vname]
	err = adapt.CheckConfig(tmpl, st, vname, view, &cfg, adapters)
	if err != nil {
		t.Errorf("CheckConfg(%q, serviceTemplate, %q, view, cfg, adapters): error %v", tmpl, vname, err)
	}

	grantRole := "viewer"
	identity := &ga4gh.Identity{
		Subject: "larry",
		Issuer:  "https://idp1.org",
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
			name: "aggregate views",
			input: &adapter.Action{
				Aggregates: []*adapter.AggregateView{
					{
						Index: 0,
						Res:   res,
						View:  res.Views["bq_read"],
					},
					{
						Index: 1,
						Res:   res,
						View:  res.Views["gcs_read"],
					},
				},
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
			expect: []clouds.MockTokenCreatorEntry{
				{
					ID:      "larry|idp1.org",
					TTL:     60 * time.Second,
					MaxTTL:  168 * time.Hour,
					NumKeys: 8,
				},
				{
					ID:      "larry|idp1.org",
					TTL:     60 * time.Second,
					MaxTTL:  168 * time.Hour,
					NumKeys: 8,
				},
			},
			fail: false,
		},
		{
			name: "too long TTL",
			input: &adapter.Action{
				Aggregates: []*adapter.AggregateView{
					{
						Index: 0,
						Res:   res,
						View:  res.Views["bq_read"],
					},
					{
						Index: 1,
						Res:   res,
						View:  res.Views["gcs_read"],
					},
				},
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
		_, _, err := adapt.MintToken(test.input)
		if test.fail != (err != nil) {
			t.Fatalf("test %q error mismatch: want error %v, got error %v", test.name, test.fail, err)
		}
		calls := warehouse.Calls()
		if err == nil && !reflect.DeepEqual(test.expect, calls) {
			t.Errorf("test %q results mismatch: want %v, got %v", test.name, test.expect, calls)
		}
	}
}
