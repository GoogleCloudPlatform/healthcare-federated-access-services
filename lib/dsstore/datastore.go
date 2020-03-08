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

// Package dsstore is a Datastore-based storage for DAM/IC.
package dsstore

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"

	glog "github.com/golang/glog" /* copybara-comment */
	"github.com/golang/protobuf/jsonpb" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
	"cloud.google.com/go/datastore" /* copybara-comment: datastore */
	"google.golang.org/api/iterator" /* copybara-comment: iterator */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
)

// storageVersion is the version of store data model.
// If there is a breaking change to the store data model, the version needs to
// be updated.

const (
	storageType    = "gcpDatastore"
	storageVersion = "v0"
	metaVersion    = "version"
)

// Data

var (
	entityKind  = "entity"
	historyKind = "history"
	metaKind    = "meta"
)

// Key is the key for items.
type Key struct {
	Datatype string `datastore:"type"`
	Realm    string `datastore:"realm"`
	User     string `datastore:"user_id"`
	ID       string `datastore:"id"`
	Rev      int64  `datastore:"rev"`
}

// Store is a datastore based implementation of storage.
type Store struct {
	client *datastore.Client

	// TODO: these fileds are only used for Info and are not related to the store.
	// Move them to lib/serviceinfo.
	//   project: the GCP project in which the datastore resides.
	project string
	//   service: the name of the service (e.g. "dam" or "ic").
	service string
	//   path:    the path to the config file.
	path string
}

// Entity is a datastore entity for data.
type Entity struct {
	Key      *datastore.Key `datastore:"__key__"`
	Service  string         `datastore:"service"`
	Datatype string         `datastore:"type"`
	Realm    string         `datastore:"realm"`
	User     string         `datastore:"user_id"`
	ID       string         `datastore:"id"`
	Rev      int64          `datastore:"rev"`
	Version  string         `datastore:"version,noindex"`
	Modified int64          `datastore:"modified"`
	Content  string         `datastore:"content,noindex"`
}

// History is an datastore entity for history.
type History struct {
	Key      *datastore.Key `datastore:"__key__"`
	Service  string         `datastore:"service"`
	Datatype string         `datastore:"type"`
	Realm    string         `datastore:"realm"`
	User     string         `datastore:"user_id"`
	ID       string         `datastore:"id"`
	Rev      int64          `datastore:"rev"`
	Version  string         `datastore:"version,noindex"`
	Modified int64          `datastore:"modified"`
	Content  string         `datastore:"content,noindex"`
}

// Meta is a datastore entity for meta.
type Meta struct {
	Key   *datastore.Key `datastore:"__key__"`
	Name  string         `datastore:"name"`
	Value string         `datastore:"value,noindex"`
}

// NewStore creates a new datastore storace and initilizes it.
// TODO: create the client for datastore in the main and inject it.
func NewStore(ctx context.Context, project, service, path string) *Store {
	client, err := datastore.NewClient(ctx, project)
	if err != nil {
		glog.Fatalf("cannot initialize datastore: %v", err)
	}
	s := New(client, project, service, path)
	if err := s.Init(context.Background()); err != nil {
		glog.Fatalf("Datastore failed to initialize: %v", err)
	}
	return s
}

// New creates a new storage.
func New(client *datastore.Client, project, service, path string) *Store {
	return &Store{
		client:  client,
		project: project,
		service: service,
		path:    path,
	}
}

// Info returns some information about the store.
// TODO: delete this and pass the information directly rather than through store.
func (s *Store) Info() map[string]string {
	return map[string]string{
		"type":    storageType,
		"version": storageVersion,
		"service": s.service,
		"path":    s.path,
	}
}

// Exists checks if a data entity with the given name exists.
func (s *Store) Exists(datatype, realm, user, id string, rev int64) (bool, error) {
	ctx := context.Background() /* TODO: pass ctx from request */
	k := datastore.NameKey(entityKind, s.newEntityKey(datatype, realm, user, id, rev), nil)
	err := s.client.Get(ctx, k, &Entity{})
	if err == datastore.ErrNoSuchEntity {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// Read reads a data entity.
func (s *Store) Read(datatype, realm, user, id string, rev int64, content proto.Message) error {
	return s.ReadTx(datatype, realm, user, id, rev, content, nil)
}

// ReadTx reads a data entity inside a transaction.
// ReadTx will not see the writes inside the transaction.
func (s *Store) ReadTx(datatype, realm, user, id string, rev int64, content proto.Message, tx storage.Tx) (ferr error) {
	if tx == nil {
		var err error
		tx, err = s.Tx(false)
		if err != nil {
			return err
		}
		defer func() {
			err := tx.Finish()
			if ferr == nil {
				ferr = err
			}
		}()
	}

	dstx, ok := tx.(*Tx)
	if !ok {
		return status.Errorf(codes.InvalidArgument, "invalid transaction")
	}

	k := datastore.NameKey(entityKind, s.newEntityKey(datatype, realm, user, id, rev), nil)
	e, err := s.newEntity(k, datatype, realm, user, id, rev, content)
	if err != nil {
		return err
	}
	if err = dstx.Tx.Get(k, e); err != nil {
		if err == datastore.ErrNoSuchEntity {
			return status.Errorf(codes.NotFound, "not found: %q", k)
		}
		return err
	}
	if err := jsonpb.Unmarshal(strings.NewReader(e.Content), content); err != nil {
		return err
	}
	return nil
}

// MultiReadTx reads a set of data entities matching the filters.
// MultiReadTx will not see the writes inside the transaction.
// If realm is "" reads all realms.
// if user is "" reads all users.
// Returns the number of items matching the filter.
// content is a map of user and id to values.
func (s *Store) MultiReadTx(datatype, realm, user string, filters [][]storage.Filter, offset, pageSize int, content map[string]map[string]proto.Message, typ proto.Message, tx storage.Tx) (_ int, ferr error) {
	ctx := context.Background() /* TODO: pass ctx from request */
	if tx == nil {
		var err error
		tx, err = s.Tx(false)
		if err != nil {
			return 0, err
		}
		defer func() {
			err := tx.Finish()
			if ferr == nil {
				ferr = err
			}
		}()
	}

	if pageSize > storage.MaxPageSize {
		pageSize = storage.MaxPageSize
	}

	q := datastore.NewQuery(entityKind).
		Filter("service =", s.service).
		Filter("type =", datatype)
	if realm != storage.AllRealms {
		q = q.Filter("realm =", realm)
	}
	if user != storage.DefaultUser {
		q = q.Filter("user_id = ", user)
	}
	q = q.Filter("rev = ", storage.LatestRev).Order("id")
	if len(filters) == 0 {
		// No post-filtering, so limit the query directly as an optimization.
		// Still can't use q.Limit(pageSize) because we want the total number of matches.
		q = q.Offset(offset)
		offset = 0
	}

	it := s.client.Run(ctx, q)
	count := 0
	for {
		var e Entity
		_, err := it.Next(&e)
		if err == iterator.Done {
			break
		}
		if err != nil {
			return 0, err
		}
		if len(e.Content) == 0 {
			continue
		}
		p := proto.Clone(typ)
		if err := jsonpb.Unmarshal(strings.NewReader(e.Content), p); err != nil {
			return 0, err
		}
		if !storage.MatchProtoFilters(filters, p) {
			continue
		}
		// Offset cannot use q.Offset(x) because it must match complex filters above.
		// For pagination, decrease any remaining offset before accepting this entry.
		if offset > 0 {
			offset--
			continue
		}
		if pageSize == 0 || pageSize > count {
			if _, ok := content[e.User]; !ok {
				content[e.User] = make(map[string]proto.Message)
			}
			content[e.User][e.ID] = p
		}
		count++
	}
	return count, nil
}

// ReadHistory reads the history.
func (s *Store) ReadHistory(datatype, realm, user, id string, content *[]proto.Message) error {
	return s.ReadHistoryTx(datatype, realm, user, id, content, nil)
}

// ReadHistoryTx reads the history inside a transaction.
func (s *Store) ReadHistoryTx(datatype, realm, user, id string, content *[]proto.Message, tx storage.Tx) (ferr error) {
	ctx := context.Background() /* TODO: pass ctx from request */
	if tx == nil {
		var err error
		tx, err = s.Tx(false)
		if err != nil {
			return err
		}
		defer func() {
			err := tx.Finish()
			if ferr == nil {
				ferr = err
			}
		}()
	}

	// TODO: handle pagination.
	q := datastore.NewQuery(historyKind).Filter("service =", s.service).
		Filter("type =", datatype).
		Filter("realm =", realm).
		Filter("user_id =", user).
		Filter("id =", id).
		Order("rev").
		Limit(storage.MaxPageSize)

	results := make([]History, storage.MaxPageSize)
	if _, err := s.client.GetAll(ctx, q, &results); err != nil {
		return err
	}

	for _, e := range results {
		if len(e.Content) == 0 {
			continue
		}
		he := &cpb.HistoryEntry{}
		if err := jsonpb.Unmarshal(strings.NewReader(e.Content), he); err != nil {
			return err
		}
		*content = append(*content, he)
	}
	return nil
}

// Write writes a data entity.
func (s *Store) Write(datatype, realm, user, id string, rev int64, content proto.Message, history proto.Message) error {
	return s.WriteTx(datatype, realm, user, id, rev, content, history, nil)
}

// WriteTx writes a data entity inside a transaction.
func (s *Store) WriteTx(datatype, realm, user, id string, rev int64, content proto.Message, history proto.Message, tx storage.Tx) (ferr error) {
	if tx == nil {
		var err error
		tx, err = s.Tx(true)
		if err != nil {
			return err
		}
		defer func() {
			err := tx.Finish()
			if ferr == nil {
				ferr = err
			}
		}()
	}
	dstx, ok := tx.(*Tx)
	if !ok {
		return status.Errorf(codes.InvalidArgument, "invalid transaction")
	}

	// TODO: ensure that the handling of last rev between write and delete are correct.

	if rev != storage.LatestRev {
		rk := datastore.NameKey(entityKind, s.newEntityKey(datatype, realm, user, id, rev), nil)
		re, err := s.newEntity(rk, datatype, realm, user, id, rev, content)
		if err != nil {
			return err
		}
		if _, err = dstx.Tx.Put(rk, re); err != nil {
			dstx.Rollback()
			return err
		}
	}

	if history != nil {
		hk := datastore.NameKey(historyKind, s.newHistoryKey(datatype, realm, user, id, rev), nil)
		he, err := s.newHistory(hk, datatype, realm, user, id, rev, history)
		if err != nil {
			dstx.Rollback()
			return err
		}
		if _, err = dstx.Tx.Put(hk, he); err != nil {
			dstx.Rollback()
			return err
		}
	}

	k := datastore.NameKey(entityKind, s.newEntityKey(datatype, realm, user, id, storage.LatestRev), nil)
	e, err := s.newEntity(k, datatype, realm, user, id, storage.LatestRev, content)
	if err != nil {
		dstx.Rollback()
		return err
	}
	if _, err := dstx.Tx.Put(k, e); err != nil {
		dstx.Rollback()
		return err
	}
	return nil
}

// Delete deletes a data entity.
func (s *Store) Delete(datatype, realm, user, id string, rev int64) error {
	return s.DeleteTx(datatype, realm, user, id, rev, nil)
}

// DeleteTx deletes a data entity inside a transaction.
func (s *Store) DeleteTx(datatype, realm, user, id string, rev int64, tx storage.Tx) (ferr error) {
	if tx == nil {
		var err error
		tx, err = s.Tx(true)
		if err != nil {
			return err
		}
		defer func() {
			err := tx.Finish()
			if ferr == nil {
				ferr = err
			}
		}()
	}

	dstx, ok := tx.(*Tx)
	if !ok {
		return status.Errorf(codes.InvalidArgument, "invalid transaction")
	}

	k := datastore.NameKey(entityKind, s.newEntityKey(datatype, realm, user, id, rev), nil)
	if err := dstx.Tx.Delete(k); err != nil {
		dstx.Rollback()
		if err == datastore.ErrNoSuchEntity {
			return status.Errorf(codes.NotFound, "not found: %q", k)
		}
		return err
	}

	return nil
}

// MultiDeleteTx deletes all records of a certain data type within a realm.
// If user is "", deletes for all users.
func (s *Store) MultiDeleteTx(datatype, realm, user string, tx storage.Tx) error {
	q := datastore.NewQuery(entityKind).
		Filter("service =", s.service).
		Filter("type =", datatype).
		Filter("realm =", realm)
	if user != storage.DefaultUser {
		q = q.Filter("user_id =", user)
	}
	q = q.Filter("rev = ", storage.LatestRev).
		Order("id")

	_, err := s.multiDelete(q)
	return err
}

// Wipe deletes all data and history within a realm.
// If realm is "" deletes for all realms.
func (s *Store) Wipe(realm string) error {
	glog.Infof("Datastore wipe project %q service %q realm %q: started", s.project, s.service, realm)
	results := make(map[string]int)
	for _, kind := range []string{historyKind, entityKind} {
		q := datastore.NewQuery(kind).
			Filter("service =", s.service)
		if realm != storage.AllRealms {
			q = q.Filter("realm =", realm)
		}
		total, err := s.multiDelete(q)
		if err != nil {
			return err
		}
		results[kind] = total
	}
	glog.Infof("Datastore wipe project %q service %q realm %q: completed results: %#v", s.project, s.service, realm, results)
	return nil
}

// multiDelete all entities matching the provided query.
// Returns the total number of items matching the query.
func (s *Store) multiDelete(q *datastore.Query) (int, error) {
	ctx := context.Background() /* TODO: pass ctx from request */
	keys, err := s.client.GetAll(ctx, q.KeysOnly(), nil)
	if err != nil {
		return 0, err
	}

	// Datastore API doesn't allow more than 500 per MultiDelete rpc.
	const multiDeleteChunkSize = 400
	total := len(keys)
	for i := 0; i < total; i += multiDeleteChunkSize {
		end := i + multiDeleteChunkSize
		if total < end {
			end = total
		}
		chunk := keys[i:end]
		if err := s.client.DeleteMulti(context.Background() /* TODO: pass ctx from request */, chunk); err != nil {
			return total, err
		}
	}
	return total, nil
}

// Tx creates a new transaction for the store.
func (s *Store) Tx(update bool) (storage.Tx, error) {
	var err error
	var dstx *datastore.Transaction
	if update {
		dstx, err = s.client.NewTransaction(context.Background() /* TODO: pass ctx from request */)
	} else {
		dstx, err = s.client.NewTransaction(context.Background() /* TODO: pass ctx from request */, datastore.ReadOnly)
	}
	if err != nil {
		return nil, err
	}
	return &Tx{
		update: update,
		Tx:     dstx,
	}, nil
}

const (
	minJitter = 1 * 1e9 // nanoseconds as integer for math
	maxJitter = 3 * 1e9 // nanoseconds as integer for math
)

// LockTx returns a storage-wide lock by the given name. Only one such lock should
// be requested at a time. If Tx is provided, it must be an update Tx.
// TODO: get rid of this function and fix the code using it.
// Note: This doesn't provide distributed mutual exclusion, don't use this.
func (s *Store) LockTx(lockName string, minFrequency time.Duration, tx storage.Tx) storage.Tx {
	if tx == nil {
		var err error
		tx, err = s.Tx(true)
		if err != nil {
			return nil
		}
		// Do not defer tx.Finish() as it must be not be freed unless the lock attempt fails.
	} else if !tx.IsUpdate() {
		return nil
	}
	entry := cpb.HistoryEntry{}
	locked := false
	for try := 0; try < 5; try++ {
		if err := s.ReadTx(storage.LockDatatype, storage.DefaultRealm, storage.DefaultUser, lockName, storage.LatestRev, &entry, tx); err == nil || storage.ErrNotFound(err) {
			// Will setup the object below.
			locked = true
			break
		}
		jitter := minJitter + rand.Float64()*(maxJitter-minJitter)
		time.Sleep(time.Duration(jitter))
	}
	if !locked {
		tx.Finish()
		return nil
	}
	if diff := time.Now().Sub(time.Unix(int64(entry.CommitTime), 0)); diff < minFrequency {
		tx.Finish()
		return nil
	}

	entry.CommitTime = float64(time.Now().Unix())
	if err := s.WriteTx(storage.LockDatatype, storage.DefaultRealm, storage.DefaultUser, lockName, storage.LatestRev, &entry, nil, tx); err != nil {
		tx.Finish()
		return nil
	}
	return tx
}

// Init initilizes the store.
// It creates some metadata information about the store on datastore.
// If metada information already exists on datastore, it comapres to see if they
// are compatible with the metadata information of the current store.
func (s *Store) Init(ctx context.Context) error {
	k := datastore.NameKey(metaKind, s.newMetaKey(metaVersion), nil)
	meta := &Meta{}
	if err := s.client.Get(context.Background() /* TODO: pass ctx from request */, k, meta); err == datastore.ErrNoSuchEntity {
		meta = &Meta{
			Key:   k,
			Name:  metaVersion,
			Value: storageVersion,
		}
		_, err := s.client.Put(context.Background() /* TODO: pass ctx from request */, k, meta)
		if err != nil {
			return status.Errorf(codes.Internal, "cannot write datastore metadata: %v", err)
		}
	} else if err != nil {
		return status.Errorf(codes.Internal, "cannot access datastore metadata: %v", err)
	}
	glog.Infof("Datastore service %q version: %s", s.service, meta.Value)
	if meta.Value != storageVersion {
		return status.Errorf(codes.FailedPrecondition, "datastore version not compatible: expected %q, got %q", storageVersion, meta.Value)
	}
	return nil
}

// Data

func (s *Store) newHistoryKey(datatype, realm, user, id string, rev int64) string {
	r := storage.LatestRevName
	if rev > 0 {
		r = fmt.Sprintf("%06d", rev)
	}
	if user == storage.DefaultUser {
		user = "~"
	}
	return fmt.Sprintf("%s/%s.%s/%s/%s/%s/%s", s.service, datatype, storage.HistoryRevName, realm, user, id, r)
}

func (s *Store) newMeta(key *datastore.Key) *Meta {
	return &Meta{
		Key:   key,
		Name:  "version",
		Value: storageVersion,
	}
}

func (s *Store) newMetaKey(id string) string {
	return fmt.Sprintf("%s/%s/%s/%s", s.service, "meta", id, "meta")
}

func (s *Store) newEntityKey(datatype, realm, user, id string, rev int64) string {
	r := storage.LatestRevName
	if rev > 0 {
		r = fmt.Sprintf("%06d", rev)
	}
	if user == storage.DefaultUser {
		user = "~"
	}
	return fmt.Sprintf("%s/%s/%s/%s/%s/%s", s.service, datatype, realm, user, id, r)
}

func (s *Store) newEntity(key *datastore.Key, datatype, realm, user, id string, rev int64, content proto.Message) (*Entity, error) {
	js, err := (&jsonpb.Marshaler{}).MarshalToString(content)
	if err != nil {
		return nil, err
	}
	return &Entity{
		Key:      key,
		Service:  s.service,
		Datatype: datatype,
		Realm:    realm,
		User:     user,
		ID:       id,
		Rev:      rev,
		Version:  storageVersion,
		Modified: time.Now().Unix(),
		Content:  js,
	}, nil
}

func (s *Store) newHistory(key *datastore.Key, datatype, realm, user, id string, rev int64, content proto.Message) (*History, error) {
	js, err := (&jsonpb.Marshaler{}).MarshalToString(content)
	if err != nil {
		return nil, err
	}
	return &History{
		Key:      key,
		Service:  s.service,
		Datatype: datatype,
		Realm:    realm,
		User:     user,
		ID:       id,
		Rev:      rev,
		Version:  storageVersion,
		Modified: time.Now().Unix(),
		Content:  js,
	}, nil
}

// Transaction

// Tx is a transaction.
type Tx struct {
	update bool
	Tx     *datastore.Transaction
}

// IsUpdate tells if the transaction is an update or read-only.
func (tx *Tx) IsUpdate() bool {
	return tx.update
}

// Finish attempts to commit a transaction.
func (tx *Tx) Finish() error {
	if tx.Tx == nil {
		return nil
	}
	_, err := tx.Tx.Commit()
	if err != nil {
		glog.Infof("datastore error committing transaction: %v", err)
		return err
	}
	tx.Tx = nil
	return nil
}

// Rollback attempts to rollback a transaction.
func (tx *Tx) Rollback() error {
	if tx.Tx == nil {
		return nil
	}
	err := tx.Tx.Rollback()
	if err != nil {
		glog.Infof("datastore error during rollback of transaction: %v", err)
		return err
	}
	// Transaction cannot be used after a rollback.
	tx.Tx = nil
	return nil
}
