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

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/adapter"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh"
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1"
)

func TestSawAdapter(t *testing.T) {
	store := storage.NewMemoryStorage("dam-static", "testdata/config")
	warehouse := clouds.NewMockTokenCreator(true)
	secretStore := storage.NewMemoryStorage("dam", "testdata/config")
	secrets := &pb.DamSecrets{}
	if err := secretStore.Read(storage.SecretsDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, secrets); err != nil {
		t.Fatalf("reading secrets file: %v", err)
	}
	adapters := &adapter.TargetAdapters{
		ByName:      make(map[string]adapter.Adapter),
		Descriptors: make(map[string]*pb.TargetAdapter),
	}
	adapt, err := adapter.NewSawAdapter(store, warehouse, secrets, adapters)
	if err != nil {
		t.Fatalf("new SAW adapter: %v", err)
	}
	var cfg pb.DamConfig
	cfgStore := storage.NewMemoryStorage("dam", "testdata/config")
	if err = cfgStore.Read(storage.ConfigDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, &cfg); err != nil {
		t.Fatalf("loading config: %v", err)
	}
	tmpl := "gcs"
	st := cfg.ServiceTemplates[tmpl]
	rname := "dataset_example"
	res := cfg.Resources[rname]
	vname := "gcs_read"
	view := res.Views[vname]
	_, err = adapt.CheckConfig(tmpl, st, rname, vname, view, &cfg, adapters)
	if err != nil {
		t.Errorf("CheckConfg(%q, serviceTemplate, %q, view, cfg, adapters): error %v", tmpl, vname, err)
	}

	paytmpl := "gcs_requester_pays"
	payst := cfg.ServiceTemplates[paytmpl]
	payres := res
	payvname := "gcs_payer"
	payview := res.Views[payvname]
	_, err = adapt.CheckConfig(paytmpl, payst, rname, payvname, payview, &cfg, adapters)
	if err != nil {
		t.Errorf("CheckConfg(%q, serviceTemplate, %q, view, cfg, adapters): error %v", paytmpl, payvname, err)
	}

	grantRole := "viewer"
	identity := &ga4gh.Identity{
		Subject: "larry",
		Issuer:  "https://idp1.org",
	}
	sRole, err := adapter.ResolveServiceRole(grantRole, view, res, &cfg)
	if err != nil {
		t.Fatalf("ResolveServiceRole(%q, %v, res, cfg): error %v", grantRole, view, err)
	}
	paysRole, err := adapter.ResolveServiceRole(grantRole, payview, payres, &cfg)
	if err != nil {
		t.Fatalf("ResolveServiceRole(%q, %v, res, cfg): error %v", grantRole, view, err)
	}

	tests := []struct {
		name   string
		input  *adapter.Action
		expect []clouds.MockTokenCreatorEntry
		fail   bool
	}{
		{
			name: "standard gcs token",
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
					Params: clouds.ResourceTokenCreationParams{
						AccountProject: "example-project-id",
						Items: []map[string]string{
							{
								"bucket":  "dataset-example-bucket1",
								"project": "dataset-example-project",
							},
							{
								"bucket":  "dataset-example-bucket2",
								"project": "dataset-example-project",
							},
						},
						Roles:       []string{"roles/storage.objectViewer"},
						Scopes:      []string{"https://www.googleapis.com/auth/cloud-platform"},
						UserProject: "example-project-id",
					},
				},
			},
			fail: false,
		},
		{
			name: "gcs requester pays token",
			input: &adapter.Action{
				Identity:        identity,
				ClientID:        "client_id",
				Config:          &cfg,
				GrantRole:       grantRole,
				MaxTTL:          168 * time.Hour,
				Resource:        payres,
				ServiceRole:     paysRole,
				ServiceTemplate: cfg.ServiceTemplates["gcs"],
				TTL:             60 * time.Second,
				View:            payview,
			},
			expect: []clouds.MockTokenCreatorEntry{
				{
					AccountID: "larry|idp1.org",
					TokenID:   "2",
					TTL:       60 * time.Second,
					MaxTTL:    168 * time.Hour,
					NumKeys:   8,
					IssuedAt:  2,
					Expires:   1002,
					Token:     "token_2",
					Params: clouds.ResourceTokenCreationParams{
						AccountProject: "example-project-id",
						Items: []map[string]string{
							{
								"bucket":  "dataset-example-payer-bucket1",
								"project": "dataset-example-project",
								"type":    "requester-pays",
							},
							{
								"bucket":  "dataset-example-payer-bucket2",
								"project": "dataset-example-project",
								"type":    "requester-pays",
							},
						},
						Roles:       []string{"roles/storage.objectViewer"},
						Scopes:      []string{"https://www.googleapis.com/auth/cloud-platform"},
						UserProject: "example-project-id",
					},
				},
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
