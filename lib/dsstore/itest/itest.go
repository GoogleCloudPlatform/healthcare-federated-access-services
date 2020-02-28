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

// Binary itest runs some code against Datastore.
package main

import (
	"context"
	"flag"
	"fmt"

	glog "github.com/golang/glog" /* copybara-comment */
	"cloud.google.com/go/datastore" /* copybara-comment: datastore */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/dsstore" /* copybara-comment: dsstore */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	dpb "github.com/golang/protobuf/ptypes/duration" /* copybara-comment */
)

var (
	fakeProjectID   = flag.String("project_id", "fake-project-id", "")
	fakeServiceName = "fake-service-name"
	fakeConfigPath  = "fake-config-path"
	fakeDataType    = "fake-datatype"
	fakeRealm       = "fake-realm"
	fakeUser        = "fake-user"
)

func main() {
	ctx := context.Background()
	flag.Parse()

	c, err := datastore.NewClient(ctx, *fakeProjectID)
	if err != nil {
		glog.Exitf("datastore.NewClient(...) failed: %v", err)
	}

	scenarioSimple(ctx, c)
	scenarioTransactionsConflictingLinearizable(ctx, c)
	scenarioTransactionsConflictingNonLinearizable(ctx, c)
	scenarioTransactionsReadAfterWrite(ctx, c)

	fmt.Println("All tests passed.")
}

func scenarioSimple(ctx context.Context, c *datastore.Client) {
	// Scenario: write, read-check, read-modify-write, read-check, delete, read-check
	id := "fake-id-simple"
	s := dsstore.New(c, *fakeProjectID, fakeServiceName, fakeConfigPath)

	{
		// Write
		tx, err := s.Tx(true)
		if err != nil {
			glog.Exitf("store.Tx(true) failed: %v", err)
		}
		entity := &dpb.Duration{Seconds: 60}
		if err := s.WriteTx(fakeDataType, fakeRealm, fakeUser, id, storage.LatestRev, entity, nil, tx); err != nil {
			glog.Exitf("store.WriteTx(...) failed: %v", err)
		}
		if err := tx.Finish(); err != nil {
			glog.Exitf("tx.Finish() failed: %v", err)
		}
	}

	{
		// Read to check it is created.
		got := &dpb.Duration{}
		if err := s.Read(fakeDataType, fakeRealm, fakeUser, id, storage.LatestRev, got); err != nil {
			glog.Exitf("store.Read(...) failed: %v", err)
		}
		want := &dpb.Duration{Seconds: 60}
		if got.GetSeconds() != want.GetSeconds() {
			glog.Exitf("store.Read(...) = %v, want %v", got, want)
		}
	}

	{
		// RMW
		tx, err := s.Tx(true)
		if err != nil {
			glog.Exitf("store.Tx(true) failed: %v", err)
		}
		resp := &dpb.Duration{}
		if err := s.ReadTx(fakeDataType, fakeRealm, fakeUser, id, storage.LatestRev, resp, tx); err != nil {
			glog.Exitf("store.ReadTx(...) failed: %v", err)
		}

		resp.Seconds = resp.Seconds + 60

		if err := s.WriteTx(fakeDataType, fakeRealm, fakeUser, id, storage.LatestRev, resp, nil, tx); err != nil {
			glog.Exitf("store.WriteTx(...) failed: %v", err)
		}
		if err := tx.Finish(); err != nil {
			glog.Exitf("tx.Finish() failed: %v", err)
		}
	}

	{
		// Read to check it is updated.
		got := &dpb.Duration{}
		if err := s.Read(fakeDataType, fakeRealm, fakeUser, id, storage.LatestRev, got); err != nil {
			glog.Exitf("store.Read(...) failed: %v", err)
		}
		want := &dpb.Duration{Seconds: 120}
		if got.GetSeconds() != want.GetSeconds() {
			glog.Exitf("store.Read(...) = %v, want %v", got, want)
		}
	}

	{
		// Delete
		tx, err := s.Tx(true)
		if err != nil {
			glog.Exitf("store.Tx(true) failed: %v", err)
		}
		if err := s.DeleteTx(fakeDataType, fakeRealm, fakeUser, id, storage.LatestRev, tx); err != nil {
			glog.Exitf("store.DeleteTx(...) failed: %v", err)
		}
		if err := tx.Finish(); err != nil {
			glog.Exitf("tx.Finish() failed: %v", err)
		}
	}

	{
		// Read to check it is deleted.
		if err := s.Read(fakeDataType, fakeRealm, fakeUser, id, storage.LatestRev, &dpb.Duration{}); status.Code(err) != codes.NotFound {
			glog.Exitf("store.Read(...) = %v, want error with code %v", err, codes.NotFound)
		}
	}
}

func scenarioTransactionsConflictingLinearizable(ctx context.Context, c *datastore.Client) {
	// Scenario: two concurrent write transactions, the second to commit prevails.
	id := "fake-id-TransactionsConflictingLinearizable"
	s := dsstore.New(c, *fakeProjectID, fakeServiceName, fakeConfigPath)

	tx1, err := s.Tx(true)
	if err != nil {
		glog.Exitf("store.Tx(true) failed: %v", err)
	}
	tx2, err := s.Tx(true)
	if err != nil {
		glog.Exitf("store.Tx(true) failed: %v", err)
	}

	if err := s.WriteTx(fakeDataType, fakeRealm, fakeUser, id, storage.LatestRev, &dpb.Duration{Seconds: 1}, nil, tx1); err != nil {
		glog.Exitf("store.WriteTx(...) failed: %v", err)
	}

	if err := s.WriteTx(fakeDataType, fakeRealm, fakeUser, id, storage.LatestRev, &dpb.Duration{Seconds: 2}, nil, tx2); err != nil {
		glog.Exitf("store.WriteTx(...) failed: %v", err)
	}

	if err := tx1.Finish(); err != nil {
		glog.Exitf("tx.Finish() failed: %v", err)
	}
	if err := tx2.Finish(); err != nil {
		glog.Exitf("tx.Finish() failed: %v", err)
	}

	got := &dpb.Duration{}
	if err := s.Read(fakeDataType, fakeRealm, fakeUser, id, storage.LatestRev, got); err != nil {
		glog.Exitf("store.Read(...) failed: %v", err)
	}
	want := &dpb.Duration{Seconds: 2}
	if got.GetSeconds() != want.GetSeconds() {
		glog.Exitf("store.Read(...) = %v, want %v", got, want)
	}
}

func scenarioTransactionsConflictingNonLinearizable(ctx context.Context, c *datastore.Client) {
	// Scenario: two concurrent RMW transactions, the second to commit fails.
	id := "fake-id-TransactionsConflictingNonLinearizable"
	s := dsstore.New(c, *fakeProjectID, fakeServiceName, fakeConfigPath)

	tx1, err := s.Tx(true)
	if err != nil {
		glog.Exitf("store.Tx(true) failed: %v", err)
	}
	tx2, err := s.Tx(true)
	if err != nil {
		glog.Exitf("store.Tx(true) failed: %v", err)
	}

	// Read so the transactions cannot be linearized.
	s.ReadTx(fakeDataType, fakeRealm, fakeUser, id, storage.LatestRev, &dpb.Duration{}, tx1)
	if err := s.WriteTx(fakeDataType, fakeRealm, fakeUser, id, storage.LatestRev, &dpb.Duration{Seconds: 1}, nil, tx1); err != nil {
		glog.Exitf("store.WriteTx(...) failed: %v", err)
	}

	// Read so the transactions cannot be linearized.
	s.ReadTx(fakeDataType, fakeRealm, fakeUser, id, storage.LatestRev, &dpb.Duration{}, tx2)
	if err := s.WriteTx(fakeDataType, fakeRealm, fakeUser, id, storage.LatestRev, &dpb.Duration{Seconds: 2}, nil, tx2); err != nil {
		glog.Exitf("store.WriteTx(...) failed: %v", err)
	}

	if err := tx1.Finish(); err != nil {
		glog.Exitf("tx.Finish() failed: %v", err)
	}
	if err := tx2.Finish(); err != datastore.ErrConcurrentTransaction {
		glog.Exitf("tx.Finish() failed: %v", err)
	}

	got := &dpb.Duration{}
	if err := s.Read(fakeDataType, fakeRealm, fakeUser, id, storage.LatestRev, got); err != nil {
		glog.Exitf("store.Read(...) failed: %v", err)
	}
	want := &dpb.Duration{Seconds: 1}
	if got.GetSeconds() != want.GetSeconds() {
		glog.Exitf("store.Read(...) = %v, want %v", got, want)
	}
}

func scenarioTransactionsReadAfterWrite(ctx context.Context, c *datastore.Client) {
	// Scenario: one transaction, write followed by read, read doesn't see the write.
	id := "fake-id-TransactionsReadAfterWrite"
	s := dsstore.New(c, *fakeProjectID, fakeServiceName, fakeConfigPath)

	{
		if err := s.Write(fakeDataType, fakeRealm, fakeUser, id, storage.LatestRev, &dpb.Duration{Seconds: 60}, nil); err != nil {
			glog.Exitf("store.WriteTx(...) failed: %v", err)
		}
	}

	{
		tx, err := s.Tx(true)
		if err != nil {
			glog.Exitf("store.Tx(true) failed: %v", err)
		}

		e := &dpb.Duration{Seconds: 120}
		if err := s.WriteTx(fakeDataType, fakeRealm, fakeUser, id, storage.LatestRev, e, nil, tx); err != nil {
			glog.Exitf("store.WriteTx(...) failed: %v", err)
		}

		got := &dpb.Duration{}
		if err := s.ReadTx(fakeDataType, fakeRealm, fakeUser, id, storage.LatestRev, got, tx); err != nil {
			glog.Exitf("store.ReadTx(...) failed: %v", err)
		}
		want := &dpb.Duration{Seconds: 60}
		if got.GetSeconds() != want.GetSeconds() {
			glog.Exitf("store.ReadTx(...) = %v, want %v", got, want)
		}

		if err := tx.Finish(); err != nil {
			glog.Exitf("tx.Finish() failed: %v", err)
		}
	}

	{
		got := &dpb.Duration{}
		if err := s.Read(fakeDataType, fakeRealm, fakeUser, id, storage.LatestRev, got); err != nil {
			glog.Exitf("store.Read(...) failed: %v", err)
		}
		want := &dpb.Duration{Seconds: 120}
		if got.GetSeconds() != want.GetSeconds() {
			glog.Exitf("store.Read(...) = %v, want %v", got, want)
		}
	}
}
