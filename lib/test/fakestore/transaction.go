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
	"sync"
	"time"

	glog "github.com/golang/glog" /* copybara-comment */
	"cloud.google.com/go/datastore" /* copybara-comment */
	"github.com/pborman/uuid" /* copybara-comment */
)

// Tx is a fake transaction.
type Tx struct {
	// source is where the state of database resides.
	// See https://bit.ly/37ANPk4
	//
	// When a Tx is created, it takes a snapshot of the state at database.
	// When a Tx is finished, it attempts to commit its changes:
	//   Read the state from source,
	//   Comparing the commit version of it with that of this transaction.
	//   If they don't match, the source's state is written to source (failure).
	//   If they match, the transaction's state is written to source (success).
	source chan State

	// mu protects the fields below.
	mu sync.Mutex
	// update determines if this is an RMW transaction or RO transaction.
	update bool
	// rolledBack determines if the transaction should be discarded.
	rolledBack bool
	// commiited determines if the transaction is commited.
	committed bool

	// state is data used by methods.
	// Read at the time that the transaction was created.
	// Can be modified.
	// Finish will write it to the source if
	//   this is an update, and
	//   change is not rolled back, and
	//   the Version at source matches the Version of state.
	state State
}

// NewTx creates a new transaction.
// update determines if the transaction is a mutation or a read-only.
func NewTx(source chan State, update bool) *Tx {
	tx := &Tx{
		update: update,
		source: source,
	}

	// Read data from source and make a copy of it.
	state := <-tx.source
	tx.source <- state
	tx.state = copyState(state)

	return tx
}

// Finish attempts to commit a transaction.
// Returns error if the transaction
// is an update, is not rolled back, and cannot be committed because of conflict.
func (tx *Tx) Finish() error {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if tx.committed || !tx.update || tx.rolledBack {
		return nil
	}

	org := <-tx.source
	if org.Version != tx.state.Version {
		glog.Infof("Concurrent Transaction Conflict:\n database: %+v\n process: %+v\n", org, tx.state)
		tx.source <- org
		return datastore.ErrConcurrentTransaction
	}
	tx.committed = true
	tx.state.Version = uuid.New()
	tx.state.LastCommit = time.Now()
	tx.source <- tx.state
	return nil
}

// Rollback attempts to rollback the transaction.
func (tx *Tx) Rollback() error {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	tx.rolledBack = true

	return nil
}

// MakeUpdate will upgrade a read-only transaction to an update transaction.
func (tx *Tx) MakeUpdate() error {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	tx.update = true
	return nil
}

// IsUpdate stated if the transaction is a mutation or read-only.
func (tx *Tx) IsUpdate() bool {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	return tx.update
}
