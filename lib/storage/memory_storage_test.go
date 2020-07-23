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

package storage

import (
	"context"
	"testing"

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
)

const (
	testStoreFileType = "store"
	testFileID        = "main"
)

func TestMemoryStorageDelete(t *testing.T) {
	store := NewMemoryStorage("storage", "testdata")
	content := &cpb.TestPersona{}
	if err := store.Read(testStoreFileType, DefaultRealm, DefaultUser, testFileID, LatestRev, content); err != nil {
		t.Errorf("reading default file: want success, got error: %v", err)
	}
	if err := store.Delete(testStoreFileType, DefaultRealm, DefaultUser, testFileID, LatestRev); err != nil {
		t.Errorf("deleting default file: want success, got error: %v", err)
	}
	if err := store.Read(testStoreFileType, DefaultRealm, DefaultUser, testFileID, LatestRev, content); err == nil {
		t.Errorf("reading deleted file: want error, got success")
	}
}

func TestMemoryStorageMultiRead(t *testing.T) {
	store := NewMemoryStorage("ic-min", "testdata/config")
	results, err := store.MultiReadTx(AccountDatatype, "test", MatchAllUsers, MatchAllIDs, nil, 0, 100, &cpb.Account{}, nil)
	if err != nil {
		t.Fatalf("MultiReadTx() failed: %v", err)
	}
	want := 4
	if len(results.Entries) != want {
		t.Errorf("MultiReadTx() length results mismatch: got %d, want %d", len(results.Entries), want)
	}
	if results.MatchCount != want {
		t.Errorf("MultiReadTx() MatchCount mismatch: got %d, want %d", results.MatchCount, want)
	}
	got := 0
	for i, entry := range results.Entries {
		if entry.Item == nil {
			t.Fatalf("MultiReadTx() invalid results: index %v item is nil", i)
		}
		if _, ok := entry.Item.(*cpb.Account); !ok {
			t.Fatalf("MultiReadTx() invalid results: index %v item is not an account", i)
		}
		got++
	}
}

func TestMemoryStorageWipe(t *testing.T) {
	realm := "test"
	user := "admin"
	ctx := context.Background()
	store := NewMemoryStorage("ic-min", "testdata/config")
	account := &cpb.Account{}
	if err := store.Read(AccountDatatype, realm, DefaultUser, user, LatestRev, account); err != nil {
		t.Fatalf("Read(%q, default, %q, %q, ...): %v", AccountDatatype, realm, user, err)
	}
	if _, err := store.Wipe(ctx, realm, 0, 0); err != nil {
		t.Fatalf("Wipe() realm %q error: %v", realm, err)
	}
	if !store.wipedRealms[realm] {
		t.Fatalf("Wipe() wiped realm %q not marked as wiped to avoid future file reads", realm)
	}
	if err := store.Read(AccountDatatype, realm, DefaultUser, user, LatestRev, account); err == nil || !ErrNotFound(err) {
		t.Fatalf("Read(%q, default, %q, %q, ...) after Wipe(): expected not found, got %v", AccountDatatype, realm, user, err)
	}
}
