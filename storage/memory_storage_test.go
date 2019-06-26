package storage

import (
	"testing"

	pb "google3/third_party/hcls_federated_access/dam/api/v1/v1"
)

const (
	testStoreFileType = "store"
	testFileID        = "main"
)

func TestMemoryStorageDelete(t *testing.T) {
	store := NewMemoryStorage("storage", "test")
	content := &pb.TestPersona{}
	if err := store.Read(testStoreFileType, DefaultRealm, testFileID, LatestRev, content); err != nil {
		t.Errorf("reading default file: want success, got error: %v", err)
	}
	if err := store.Delete(testStoreFileType, DefaultRealm, testFileID, LatestRev); err != nil {
		t.Errorf("deleting default file: want success, got error: %v", err)
	}
	if err := store.Read(testStoreFileType, DefaultRealm, testFileID, LatestRev, content); err == nil {
		t.Errorf("reading deleted file: want error, got success")
	}
}
