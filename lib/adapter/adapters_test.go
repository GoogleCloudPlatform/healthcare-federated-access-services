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
	"reflect"
	"testing"

	"github.com/golang/protobuf/proto" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/adapter" /* copybara-comment: adapter */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds" /* copybara-comment: clouds */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/globalflags" /* copybara-comment: globalflags */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/kms/localsign" /* copybara-comment: localsign */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
)

const (
	expectedNumOfAdapters = 4
)

func TestCreateAdapters(t *testing.T) {
	store := storage.NewMemoryStorage("dam-static", "testdata/config")
	warehouse := clouds.NewMockTokenCreator(false)
	secretStore := storage.NewMemoryStorage("dam", "testdata/config")
	secrets := &pb.DamSecrets{}
	if err := secretStore.Read(storage.SecretsDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, secrets); err != nil {
		t.Fatalf("reading secrets file: %v", err)
	}

	key := testkeys.Default
	signer := localsign.New(&key)
	adapters, err := adapter.CreateAdapters(store, warehouse, signer)
	if err != nil {
		t.Fatalf("CreateAdapters(store, warehouse): want success, got error: %v", err)
	}
	if len(adapters.ByAdapterName) != expectedNumOfAdapters {
		t.Errorf("count ByName: want %d, got %d", expectedNumOfAdapters, len(adapters.ByAdapterName))
	}
	if len(adapters.ByServiceName) != len(adapters.Descriptors) {
		t.Errorf("count Descriptors should be same as count ByName: want %d, got %d", len(adapters.ByServiceName), len(adapters.Descriptors))
	}
	for name, item := range adapters.ByServiceName {
		if _, ok := adapters.Descriptors[name]; !ok {
			t.Errorf("entry %q appears in ByName but not in Descriptors", name)
		}
		if item == nil {
			t.Errorf("entry %q: want not nil, got nil", name)
		}
	}
	for name, desc := range adapters.Descriptors {
		if desc == nil {
			t.Errorf("descriptor %q: want not nil, got nil", name)
		}
		are, ok := adapters.VariableREs[name]
		if !ok {
			t.Fatalf("descriptor %q variable RE missing", name)
		}
		for varName := range desc.ItemVariables {
			if _, ok := are[varName]; !ok {
				t.Fatalf("descriptor %q variable %q RE entry missing", name, varName)
			}
		}
	}
}

func TestGetItemVariables(t *testing.T) {
	store := storage.NewMemoryStorage("dam-static", "testdata/config")
	warehouse := clouds.NewMockTokenCreator(false)
	secretStore := storage.NewMemoryStorage("dam", "testdata/config")
	secrets := &pb.DamSecrets{}
	if err := secretStore.Read(storage.SecretsDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, secrets); err != nil {
		t.Fatalf("reading secrets file: %v", err)
	}
	key := testkeys.Default
	signer := localsign.New(&key)
	adapters, err := adapter.CreateAdapters(store, warehouse, signer)
	if err != nil {
		t.Fatalf("CreateAdapters(store, warehouse): want success, got error: %v", err)
	}
	tests := []struct {
		name    string
		service string
		item    *pb.View_Item
		expect  map[string]string
		fail    bool
	}{
		{
			name:    "nil vars",
			service: "gcs",
			item:    &pb.View_Item{},
			fail:    false,
		},
		{
			name:    "empty vars",
			service: "gcs",
			item: &pb.View_Item{
				Args: map[string]string{},
			},
			expect: map[string]string{},
			fail:   false,
		},
		{
			name:    "bad variable name",
			service: "gcs",
			item: &pb.View_Item{
				Args: map[string]string{
					"foo": "bar",
				},
			},
			fail: true,
		},
		{
			name:    "bad variable format",
			service: "gcs",
			item: &pb.View_Item{
				Args: map[string]string{
					"bucket": "#$%#$%#$#",
				},
			},
			fail: true,
		},
		{
			name:    "good project and bucket",
			service: "gcs",
			item: &pb.View_Item{
				Args: map[string]string{
					"project": "foo",
					"bucket":  "bar",
				},
			},
			expect: map[string]string{
				"project": "foo",
				"bucket":  "bar",
			},
			fail: false,
		},
	}
	for _, tc := range tests {
		result, _, err := adapter.GetItemVariables(adapters, tc.service, tc.item)
		if tc.fail != (err != nil) {
			t.Fatalf("test %q error mismatch: want error %v, got error %v", tc.name, tc.fail, err)
		}
		if err == nil && !reflect.DeepEqual(result, tc.expect) {
			t.Errorf("test %q results mismatch: want %v, got %v", tc.name, tc.expect, result)
		}
	}
}

func TestResolveServiceRole(t *testing.T) {
	store := storage.NewMemoryStorage("dam", "testdata/config")
	var cfg pb.DamConfig
	err := store.Read(storage.ConfigDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, &cfg)
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}
	res := cfg.Resources["dataset_example"]
	view := res.Views["gcs_read"]
	tests := []struct {
		role   string
		expect string
		fail   bool
	}{
		{
			role:   "viewer",
			expect: "File Viewer",
			fail:   false,
		},
		{
			role: "bad_role",
			fail: true,
		},
	}
	for _, test := range tests {
		result, err := adapter.ResolveServiceRole(test.role, view, res, &cfg)
		if test.fail != (err != nil) {
			t.Fatalf("test %q error mismatch: want error %v, got error %v", test.role, test.fail, err)
		}
		if err == nil && result == nil {
			t.Fatalf("test %q returned success but returned nil result", test.role)
		}
		if err == nil && test.expect != result.Ui["label"] {
			t.Errorf("test %q results mismatch: want %v, got %v", test.role, test.expect, result.Ui["label"])
		}
	}
}

func TestExperimentalVarsCheck(t *testing.T) {
	store := storage.NewMemoryStorage("dam-static", "testdata/config")
	warehouse := clouds.NewMockTokenCreator(false)
	secretStore := storage.NewMemoryStorage("dam", "testdata/config")
	secrets := &pb.DamSecrets{}
	if err := secretStore.Read(storage.SecretsDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, secrets); err != nil {
		t.Fatalf("reading secrets file: %v", err)
	}
	key := testkeys.Default
	signer := localsign.New(&key)
	adapters, err := adapter.CreateAdapters(store, warehouse, signer)
	if err != nil {
		t.Fatalf("CreateAdapters(store, warehouse): want success, got error: %v", err)
	}
	desc := adapters.Descriptors[adapter.SawAdapterName]
	d := pb.ServiceDescriptor{}
	proto.Merge(&d, desc)

	fakeDesc := "fake"
	fakeVar := "testing"
	fakeVarValue := "test_value"

	d.ItemVariables = map[string]*pb.VariableFormat{
		fakeVar: &pb.VariableFormat{
			Regexp:       ".",
			Optional:     true,
			Experimental: true,
		},
	}
	adapters.Descriptors[fakeDesc] = &d

	original := globalflags.Experimental
	defer func() { globalflags.Experimental = original }()
	globalflags.Experimental = true

	item := &pb.View_Item{Args: map[string]string{fakeVar: fakeVarValue}}
	vars, path, err := adapter.GetItemVariables(adapters, fakeDesc, item)
	if err != nil {
		t.Fatalf("GetItemVariables(adapters, %q, %+v) failed at path %q: %v", fakeDesc, item, path, err)
	}
	if got, ok := vars[fakeVar]; !ok || got != fakeVarValue {
		t.Fatalf("item variable value not found or mismatch: got %q, want %q", got, fakeVarValue)
	}

	// Now test again with only one change to isolate Experimental behavior.
	globalflags.Experimental = false
	vars, _, err = adapter.GetItemVariables(adapters, fakeDesc, item)
	if err == nil {
		t.Fatalf("GetItemVariables(adapters, %q, %+v) returned experimental variables in non-experimental mode: vars %+v", fakeDesc, item, vars)
	}
}
