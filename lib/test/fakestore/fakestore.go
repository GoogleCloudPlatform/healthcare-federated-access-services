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

// Package fakestore provides a fake in-mem storage.
// The implementation is based on the current real implementation using Datastore.
// See /lib/dsstore/
// TODO: once we have a fake Datastore server, get rid of this.
package fakestore

import (
	"fmt"
	"sort"
	"time"

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
)

// Rev gives the string value of a revision.
func Rev(rev int64) string {
	if rev == storage.LatestRev {
		return storage.LatestRevName
	}
	return fmt.Sprintf("%06d", rev)
}

// Store is a fake in-mem store of data.
type Store struct {
	// Information map.
	Information map[string]string
	// State is where the data resides.
	// Any block of code that wants to access the state reads it from the chan,
	// performs its operations, and then writes it back to the chan.
	// See https://bit.ly/37ANPk4
	State chan State
}

// New creates a new Store.
func New() *Store {
	f := &Store{State: make(chan State, 1)}
	state := State{
		Data:    make(Data),
		History: make(Data),
	}
	f.State <- state
	return f
}

// Tx creates a new transaction.
func (s *Store) Tx(update bool) (storage.Tx, error) {
	return NewTx(s.State, update), nil
}

// Info returns information about the storage.
func (s *Store) Info() map[string]string {
	return s.Information
}

// Exists checks if data item with given key exists.
func (s *Store) Exists(datatype, realm, user, id string, rev int64) (_ bool, ferr error) {
	ntx, err := s.Tx(false)
	if err != nil {
		return false, err
	}
	defer func() {
		err := ntx.Finish()
		if ferr == nil {
			ferr = err
		}
	}()

	ntx.(*Tx).mu.Lock()
	defer ntx.(*Tx).mu.Unlock()
	return s.exists(datatype, realm, user, id, rev, ntx.(*Tx).state)
}

func (s *Store) exists(datatype, realm, user, id string, rev int64, state State) (bool, error) {
	key := Key{datatype, realm, user, id, Rev(rev)}
	if _, ok := state.Data[key]; !ok {
		return false, nil
	}
	return true, nil
}

// Read reads a data item of a given key.
func (s *Store) Read(datatype, realm, user, id string, rev int64, content proto.Message) error {
	return s.ReadTx(datatype, realm, user, id, rev, content, nil)
}

// ReadTx reads a data item of a given key inside a transaction.
// Calls Read if transaction is nil.
func (s *Store) ReadTx(datatype, realm, user, id string, rev int64, content proto.Message, tx storage.Tx) (ferr error) {
	ntx := tx
	if ntx == nil {
		var err error
		ntx, err = s.Tx(false)
		if err != nil {
			return err
		}
		// We need to call finish for this transaction.
		// We need to update the error returned from the function if commit fails.
		defer func() {
			err := ntx.Finish()
			if ferr == nil {
				ferr = err
			}
		}()
	}

	ntx.(*Tx).mu.Lock()
	defer ntx.(*Tx).mu.Unlock()
	return s.read(datatype, realm, user, id, rev, content, ntx.(*Tx).state)
}

func (s *Store) read(datatype, realm, user, id string, rev int64, content proto.Message, state State) error {
	key := Key{datatype, realm, user, id, Rev(rev)}
	v, ok := state.Data[key]
	if !ok {
		return status.Errorf(codes.NotFound, "not found: %+v rev:%v", key, rev)
	}

	content.Reset()
	proto.Merge(content, v)
	return nil
}

// MultiReadTx reads a set of items matching the input parameters and filters.
// Returns total count and error.
//
// content will contain the items which
//   their key matches the provided datatype, realm, user (if realm/user are not "")
//   their value matches the provider filers
// Items are sorted by their key's user and id in ascending order.
// The type of the item's value should be typ.
// Last revision of the items is used.
//
// content's maps are keyed by user and id of the keys.
func (s *Store) MultiReadTx(
	datatype, realm, user string,
	filters [][]storage.Filter,
	offset, pageSize int,
	content map[string]map[string]proto.Message,
	typ proto.Message,
	tx storage.Tx,
) (_ int, ferr error) {
	ntx := tx
	if ntx == nil {
		var err error
		ntx, err = s.Tx(false)
		if err != nil {
			return 0, err
		}
		defer func() {
			err := ntx.Finish()
			if ferr == nil {
				ferr = err
			}
		}()
	}

	ntx.(*Tx).mu.Lock()
	defer ntx.(*Tx).mu.Unlock()
	return s.multiRead(datatype, realm, user, filters, offset, pageSize, content, typ, ntx.(*Tx).state)
}

func (s *Store) multiRead(
	datatype, realm, user string,
	filters [][]storage.Filter,
	offset, pageSize int,
	content map[string]map[string]proto.Message,
	typ proto.Message,
	state State,
) (int, error) {
	if content == nil {
		return 0, status.Error(codes.InvalidArgument, "content cannot be nil")
	}
	if len(content) != 0 {
		return 0, status.Error(codes.InvalidArgument, "content is not empty")
	}

	var res KVList
	for k, v := range state.Data {
		if k.Datatype != datatype {
			continue
		}
		if k.Realm != "" && k.Realm != realm {
			continue
		}
		if k.User != "" && k.User != user {
			continue
		}
		if k.Rev != storage.LatestRevName {
			continue
		}

		if !storage.MatchProtoFilters(filters, v) {
			continue
		}

		// TODO: check the type of v matches the type of typ

		res = append(res, KV{k, v})
	}

	sort.Sort(res)

	i := offset
	for ; i < len(res) && i < offset+pageSize; i++ {
		k := res[i].K
		v := res[i].V
		if _, ok := content[k.User]; !ok {
			content[k.User] = make(map[string]proto.Message)
		}
		content[k.User][k.ID] = proto.Clone(v)
	}

	return i - offset, nil
}

// ReadHistory reads the history of a given key.
func (s *Store) ReadHistory(datatype, realm, user, id string, content *[]proto.Message) error {
	return s.ReadHistoryTx(datatype, realm, user, id, content, nil)
}

// ReadHistoryTx reads the history of a given key inside a transaction.
func (s *Store) ReadHistoryTx(datatype, realm, user, id string, content *[]proto.Message, tx storage.Tx) (ferr error) {
	ntx := tx
	if ntx == nil {
		var err error
		ntx, err = s.Tx(false)
		if err != nil {
			return err
		}
		defer func() {
			err := ntx.Finish()
			if ferr == nil {
				ferr = err
			}
		}()
	}

	ntx.(*Tx).mu.Lock()
	defer ntx.(*Tx).mu.Unlock()
	return s.readHistory(datatype, realm, user, id, content, ntx.(*Tx).state)
}

// readHistory reads the history of a given key inside a transaction.
func (s *Store) readHistory(datatype, realm, user, id string, content *[]proto.Message, state State) error {
	if content == nil {
		return status.Error(codes.NotFound, "content cannot be nil")
	}
	key := Key{datatype, realm, user, id, ""}

	var res []proto.Message
	for k, v := range state.History {
		k.Rev = ""
		if k != key {
			continue
		}
		res = append(res, proto.Clone(v))
	}
	*content = res
	return nil
}

// Write writes an item.
func (s *Store) Write(datatype, realm, user, id string, rev int64, content proto.Message, history proto.Message) error {
	return s.WriteTx(datatype, realm, user, id, rev, content, history, nil)
}

// WriteTx writes an item inside a transaction.
func (s *Store) WriteTx(datatype, realm, user, id string, rev int64, content proto.Message, history proto.Message, tx storage.Tx) (ferr error) {
	ntx := tx
	if ntx == nil {
		var err error
		ntx, err = s.Tx(true)
		if err != nil {
			return err
		}
		defer func() {
			err := ntx.Finish()
			if ferr == nil {
				ferr = err
			}
		}()
	}

	ntx.(*Tx).mu.Lock()
	defer ntx.(*Tx).mu.Unlock()
	return s.write(datatype, realm, user, id, rev, content, history, ntx.(*Tx).state)
}

func (s *Store) write(datatype, realm, user, id string, rev int64, content proto.Message, history proto.Message, state State) error {
	key := Key{datatype, realm, user, id, Rev(rev)}
	state.Data[key] = proto.Clone(content)
	if rev != storage.LatestRev {
		latest := key
		latest.Rev = Rev(storage.LatestRev)
		state.Data[latest] = proto.Clone(content)
	}
	if history != nil {
		state.History[key] = proto.Clone(history)
	}
	return nil
}

// Delete deletes an item.
func (s *Store) Delete(datatype, realm, user, id string, rev int64) error {
	return s.DeleteTx(datatype, realm, user, id, rev, nil)
}

// DeleteTx deletes an item inside a transaction.
func (s *Store) DeleteTx(datatype, realm, user, id string, rev int64, tx storage.Tx) (ferr error) {
	ntx := tx
	if ntx == nil {
		var err error
		ntx, err = s.Tx(true)
		if err != nil {
			return err
		}
		defer func() {
			err := ntx.Finish()
			if ferr == nil {
				ferr = err
			}
		}()
	}

	ntx.(*Tx).mu.Lock()
	defer ntx.(*Tx).mu.Unlock()
	return s.delete(datatype, realm, user, id, rev, ntx.(*Tx).state)
}

func (s *Store) delete(datatype, realm, user, id string, rev int64, state State) error {
	key := Key{datatype, realm, user, id, Rev(rev)}
	delete(state.Data, key)
	return nil
}

// MultiDeleteTx deletes an item inside a transaction.
func (s *Store) MultiDeleteTx(datatype, realm, user string, tx storage.Tx) (ferr error) {
	ntx := tx
	if ntx == nil {
		var err error
		ntx, err = s.Tx(true)
		if err != nil {
			return err
		}
		defer func() {
			err := ntx.Finish()
			if ferr == nil {
				ferr = err
			}
		}()
	}

	ntx.(*Tx).mu.Lock()
	defer ntx.(*Tx).mu.Unlock()
	return s.multiDelete(datatype, realm, user, ntx.(*Tx).state)
}

func (s *Store) multiDelete(datatype, realm, user string, state State) error {
	for k := range state.Data {
		if k.Datatype == datatype && k.Realm == realm && k.User == user {
			delete(state.Data, k)
		}
	}
	return nil
}

// Wipe clears a realm.
func (s *Store) Wipe(realm string) (ferr error) {
	ntx, err := s.Tx(true)
	if err != nil {
		return err
	}
	defer func() {
		err := ntx.Finish()
		if ferr == nil {
			ferr = err
		}
	}()

	ntx.(*Tx).mu.Lock()
	defer ntx.(*Tx).mu.Unlock()
	return s.wipe(realm, ntx.(*Tx).state)
}

func (s *Store) wipe(realm string, state State) error {
	for k := range state.Data {
		if k.Realm == realm {
			delete(state.Data, k)
		}
	}
	return nil
}

// LockTx creates a lock with the give name.
func (s *Store) LockTx(lockName string, minFrequency time.Duration, tx storage.Tx) storage.Tx {
	// TODO: not sure about the behavior for this one.
	return tx
}

var _ storage.Store = &Store{}
