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

package permissions

import (
	"context"
	"testing"
	"time"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/kms/localsign" /* copybara-comment: localsign */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
)

const (
	testConfigPath = "testdata/config"
	testService    = "permissions"
)

func TestAdmin(t *testing.T) {
	store := storage.NewMemoryStorage(testService, testConfigPath)

	perm := New(store)

	type adminTest struct {
		name             string
		subject          string
		identities       []string
		linkedIdentities string
		want             bool
	}

	tests := []adminTest{
		{
			name:             "admin user in subject",
			subject:          "admin@example.com",
			identities:       []string{},
			linkedIdentities: "",
			want:             true,
		},
		{
			name:             "admin user in identities",
			subject:          "no_admin@example.com",
			identities:       []string{"admin@example.com"},
			linkedIdentities: "",
			want:             true,
		},
		{
			name:             "admin user in linkedIdentities",
			subject:          "no_admin@example.com",
			identities:       []string{},
			linkedIdentities: "admin@example.com,https://example.com/oidc",
			want:             true,
		},
		{
			name:             "not admin user",
			subject:          "no_admin@example.com",
			identities:       []string{},
			linkedIdentities: "",
			want:             false,
		},
		{
			name:             "admin expired",
			subject:          "expire_admin@example.com",
			identities:       []string{},
			linkedIdentities: "",
			want:             false,
		},
		{
			name:             "admin expired",
			subject:          "expire_admin@example.com",
			identities:       []string{},
			linkedIdentities: "",
			want:             false,
		},
		{
			name:             "admin expired",
			subject:          "expire_admin@example.com",
			identities:       []string{},
			linkedIdentities: "",
			want:             false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			identities := make(map[string][]string)
			for _, identity := range tc.identities {
				identities[identity] = []string{}
			}
			d := &ga4gh.VisaData{
				Assertion: ga4gh.Assertion{
					Type:  ga4gh.LinkedIdentities,
					Value: ga4gh.Value(tc.linkedIdentities),
				},
			}

			signer := localsign.New(&testkeys.Default)
			ctx := context.Background()
			v, err := ga4gh.NewVisaFromData(ctx, d, ga4gh.JWTEmptyJKU, signer)
			if err != nil {
				t.Fatalf("ga4gh.NewVisaFromData failed: %v", err)
			}

			id := &ga4gh.Identity{
				Subject:    tc.subject,
				Identities: identities,
				VisaJWTs:   []string{string(v.JWT())},
			}
			isAdmin, err := perm.CheckAdmin(id)
			if err != nil {
				t.Fatalf("CheckAdmin() failed: %v", err)
			}
			if isAdmin != tc.want {
				t.Errorf("CheckAdmin() = %v, wants %v", isAdmin, tc.want)
			}
		})
	}
}

func Test_cache(t *testing.T) {
	store := storage.NewMemoryStorage(testService, testConfigPath)

	perm := New(store)

	// first loadPermission should load permission from store
	p1, err := perm.loadPermissions()
	if err != nil {
		t.Fatalf("loadPermissions() failed: %v", err)
	}

	if p1.Version != "v0" {
		t.Errorf("Version = %s, wants %s", p1.Version, "v0")
	}

	// update permission in store
	save := &cpb.Permissions{Version: "v1"}
	if err := store.Write(storage.PermissionsDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, save, nil); err != nil {
		t.Fatalf("Write permissions failed: %v", err)
	}

	// cache still valid, did not read from store
	p2, err := perm.loadPermissions()
	if err != nil {
		t.Fatalf("loadPermissions() failed: %v", err)
	}

	if p2.Version != "v0" {
		t.Errorf("Version = %s, wants %s", p2.Version, "v0")
	}

	// cache expired, read from store
	perm.cacheExpiry = time.Now().Add(-1 * time.Minute)
	p3, err := perm.loadPermissions()
	if err != nil {
		t.Fatalf("loadPermissions() failed: %v", err)
	}

	if p3.Version != "v1" {
		t.Errorf("Version = %s, wants %s", p3.Version, "v1")
	}
}
