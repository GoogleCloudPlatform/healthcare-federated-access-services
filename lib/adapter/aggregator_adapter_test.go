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
	"reflect"
	"testing"
	"time"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/adapter" /* copybara-comment: adapter */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds" /* copybara-comment: clouds */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
)

func TestAggregatorAdapter(t *testing.T) {
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
	saws, err := adapter.NewSawAdapter(warehouse)
	if err != nil {
		t.Fatalf("error creating SAW adapter: %v", err)
	}
	adapters.ByAdapterName[adapter.SawAdapterName] = saws
	for k, v := range saws.Descriptors() {
		adapters.ByServiceName[k] = saws
		adapters.Descriptors[k] = v
	}

	adapt, err := adapter.NewAggregatorAdapter(adapters)
	if err != nil {
		t.Fatalf("new aggregator adapter: %v", err)
	}
	adapters.ByAdapterName[adapter.SawAdapterName] = adapt
	for k, v := range adapt.Descriptors() {
		adapters.ByServiceName[k] = adapt
		adapters.Descriptors[k] = v
	}
	var cfg pb.DamConfig
	cfgStore := storage.NewMemoryStorage("dam", "testdata/config")
	if err = cfgStore.Read(storage.ConfigDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, &cfg); err != nil {
		t.Fatalf("loading config: %v", err)
	}
	tmpl := "views"
	st := cfg.ServiceTemplates[tmpl]
	rname := "dataset_example"
	res := cfg.Resources[rname]
	vname := "gcp"
	view := res.Views[vname]
	_, err = adapt.CheckConfig(tmpl, st, rname, vname, view, &cfg, adapters)
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
				Resource:        res,
				ServiceRole:     sRole,
				ServiceTemplate: st,
				TTL:             60 * time.Second,
				View:            view,
			},
			expect: []clouds.MockTokenCreatorEntry{
				{
					AccountID: "larry|idp1.org",
					TokenID:   "1",
					TTL:       60 * time.Second,
					MaxTTL:    168 * time.Hour,
					NumKeys:   8,
					IssuedAt:  1,
					Expires:   1001,
					Token:     "token_1",
				},
				{
					AccountID: "larry|idp1.org",
					TokenID:   "2",
					TTL:       60 * time.Second,
					MaxTTL:    168 * time.Hour,
					NumKeys:   8,
					IssuedAt:  2,
					Expires:   1002,
					Token:     "token_2",
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
				ResourceID:      rname,
				Resource:        res,
				ServiceRole:     sRole,
				ServiceTemplate: st,
				TTL:             400 * time.Hour,
				ViewID:          vname,
				View:            view,
			},
			fail: true,
		},
	}
	for _, test := range tests {
		_, err := adapt.MintToken(context.Background(), test.input)
		if test.fail != (err != nil) {
			t.Fatalf("test %q error mismatch: want error %v, got error %v", test.name, test.fail, err)
		}
		calls := warehouse.Calls()
		if err == nil && !reflect.DeepEqual(test.expect, calls) {
			t.Errorf("test %q results mismatch: want %v, got %v", test.name, test.expect, calls)
		}
	}
}
