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

package fakestore

import (
	"testing"

	"cloud.google.com/go/datastore" /* copybara-comment */
	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	dpb "github.com/golang/protobuf/ptypes/duration" /* copybara-comment */
)

func TestStore_WriteTxReadTx_SameTx(t *testing.T) {
	s := New()

	tx, err := s.Tx(true)
	if err != nil {
		t.Fatalf("store.Tx(true) failed: %v", err)
	}
	tx.Finish()

	want := &dpb.Duration{Seconds: 60}
	err = s.WriteTx("fake-datatype", "fake-real", "fake-user", "fake-id", storage.LatestRev, want, nil, tx)
	if err != nil {
		t.Fatalf("store.WriteTx(...) failed: %v", err)
	}

	got := &dpb.Duration{}
	err = s.ReadTx("fake-datatype", "fake-real", "fake-user", "fake-id", storage.LatestRev, got, tx)
	if err != nil {
		t.Fatalf("store.WriteTx(...) failed: %v", err)
	}

	if diff := cmp.Diff(got, want, protocmp.Transform()); diff != "" {
		t.Errorf("ServeHTTP(w,r); diff (-want +got):\n%s", diff)
	}
}

func TestStore_WriteTxReadTx_SeparateTx(t *testing.T) {
	s := New()

	want := &dpb.Duration{Seconds: 60}
	err := s.Write("fake-datatype", "fake-real", "fake-user", "fake-id", storage.LatestRev, want, nil)
	if err != nil {
		t.Fatalf("store.WriteTx(...) failed: %v", err)
	}

	got := &dpb.Duration{}
	err = s.Read("fake-datatype", "fake-real", "fake-user", "fake-id", storage.LatestRev, got)
	if err != nil {
		t.Fatalf("store.WriteTx(...) failed: %v", err)
	}

	if diff := cmp.Diff(got, want, protocmp.Transform()); diff != "" {
		t.Errorf("ServeHTTP(w,r); diff (-want +got):\n%s", diff)
	}
}

func TestStore_Tx_NoConflict(t *testing.T) {
	s := New()

	tx, err := s.Tx(true)
	if err != nil {
		t.Fatalf("store.Tx(true) failed: %v", err)
	}
	tx.Finish()
	if err := tx.Finish(); err != nil {
		t.Fatalf("tx.Finish() failed: %v", err)
	}

	ntx, err := s.Tx(true)
	if err != nil {
		t.Fatalf("store.Tx(true) failed: %v", err)
	}
	if err := ntx.Finish(); err != nil {
		t.Fatalf("ntx.Finish() failed: %v", err)
	}
}

func TestStore_Tx_Conflict(t *testing.T) {
	s := New()

	tx, err := s.Tx(true)
	if err != nil {
		t.Fatalf("store.Tx(true) failed: %v", err)
	}

	ntx, err := s.Tx(true)
	if err != nil {
		t.Fatalf("store.Tx(true) failed: %v", err)
	}
	if err := ntx.Finish(); err != nil {
		t.Fatalf("ntx.Finish() failed: %v", err)
	}

	if err := tx.Finish(); err != datastore.ErrConcurrentTransaction {
		t.Fatalf("tx.Finish() should fail when there has been a conflicting update transaction")
	}
}
