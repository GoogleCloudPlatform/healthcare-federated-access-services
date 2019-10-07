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

package gcp_storage

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	glog "github.com/golang/glog"
	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
	"cloud.google.com/go/datastore"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage"

	// TODO: this should be more generic, not DAM pb.
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1"
)

const (
	storageType    = "gcpDatastore"
	storageVersion = "v0"

	entityKind  = "entity"
	historyKind = "history"
	metaKind    = "meta"

	metaVersion = "version"
	maxPageSize = 1000

	multiDeleteChunkSize = 400 // must not exceed 500 as per Datastore API
)

var (
	mutex     = &sync.Mutex{}
	wipeKinds = []string{historyKind, entityKind}
)

type DatastoreStorage struct {
	project string
	service string
	path    string
	client  *datastore.Client
	ctx     context.Context
}

type DatastoreEntity struct {
	Key      *datastore.Key `datastore:"__key__"`
	Service  string         `datastore:"service"`
	Datatype string         `datastore:"type"`
	Realm    string         `datastore:"realm"`
	User     string         `datastore:"user_id"`
	Id       string         `datastore:"id"`
	Rev      int64          `datastore:"rev"`
	Version  string         `datastore:"version,noindex"`
	Modified int64          `datastore:"modified"`
	Content  string         `datastore:"content,noindex"`
}

type DatastoreHistory struct {
	Key      *datastore.Key `datastore:"__key__"`
	Service  string         `datastore:"service"`
	Datatype string         `datastore:"type"`
	Realm    string         `datastore:"realm"`
	User     string         `datastore:"user_id"`
	Id       string         `datastore:"id"`
	Rev      int64          `datastore:"rev"`
	Version  string         `datastore:"version,noindex"`
	Modified int64          `datastore:"modified"`
	Content  string         `datastore:"content,noindex"`
}

type DatastoreMeta struct {
	Key   *datastore.Key `datastore:"__key__"`
	Name  string         `datastore:"name"`
	Value string         `datastore:"value,noindex"`
}

func NewDatastoreStorage(ctx context.Context, project, service, path string) *DatastoreStorage {
	client, err := datastore.NewClient(ctx, project)
	if err != nil {
		glog.Fatalf("cannot initialize datastore: %v", err)
	}
	s := &DatastoreStorage{
		project: project,
		service: service,
		path:    path,
		client:  client,
		ctx:     ctx,
	}
	if err = s.init(); err != nil {
		glog.Fatalf("Datastore failed to initialize: %v", err)
	}

	return s
}

func (s *DatastoreStorage) Info() map[string]string {
	return map[string]string{
		"type":    storageType,
		"version": storageVersion,
		"service": s.service,
		"path":    s.path,
	}
}

func (s *DatastoreStorage) Exists(datatype, realm, user, id string, rev int64) (bool, error) {
	k := datastore.NameKey(entityKind, s.entityKey(datatype, realm, user, id, rev), nil)
	e := new(DatastoreEntity)
	err := s.client.Get(s.ctx, k, e)
	if err == nil {
		return true, nil
	} else if err == datastore.ErrNoSuchEntity {
		return false, nil
	}
	return false, err
}

func (s *DatastoreStorage) Read(datatype, realm, user, id string, rev int64, content proto.Message) error {
	return s.ReadTx(datatype, realm, user, id, rev, content, nil)
}

func (s *DatastoreStorage) ReadTx(datatype, realm, user, id string, rev int64, content proto.Message, tx storage.Tx) error {
	if tx == nil {
		var err error
		tx, err = s.Tx(false)
		if err != nil {
			return err
		}
		defer tx.Finish()
	}
	dstx, ok := tx.(*DatastoreTx)
	if !ok {
		return fmt.Errorf("invalid transaction")
	}

	k := datastore.NameKey(entityKind, s.entityKey(datatype, realm, user, id, rev), nil)
	e, err := s.datastoreEntity(k, datatype, realm, user, id, rev, content)
	if err != nil {
		return err
	}
	if err = dstx.Tx.Get(k, e); err != nil {
		if err == datastore.ErrNoSuchEntity {
			return fmt.Errorf("not found: %q", k)
		}
		return err
	}
	if err := jsonpb.Unmarshal(strings.NewReader(e.Content), content); err != nil {
		return err
	}
	return nil
}

func (s *DatastoreStorage) MultiReadTx(datatype, realm, user string, content map[string]map[string]proto.Message, typ proto.Message, tx storage.Tx) error {
	if tx == nil {
		var err error
		tx, err = s.Tx(false)
		if err != nil {
			return err
		}
		defer tx.Finish()
	}

	// TODO: handle pagination.
	q := datastore.NewQuery(entityKind).Filter("service =", s.service).Filter("type =", datatype).Filter("realm =", realm)
	if user != storage.DefaultUser {
		q = q.Filter("user_id = ", user)
	}
	q = q.Filter("rev = ", storage.LatestRev).Order("id").Limit(maxPageSize)
	results := make([]DatastoreEntity, maxPageSize)
	if _, err := s.client.GetAll(s.ctx, q, &results); err != nil {
		return err
	}
	for _, e := range results {
		if len(e.Content) == 0 {
			continue
		}
		// v := reflect.New(reflect.TypeOf(typ))
		// p := v.Elem().Interface().(proto.Message)
		p := proto.Clone(typ)
		if err := jsonpb.Unmarshal(strings.NewReader(e.Content), p); err != nil {
			return err
		}
		userContent, ok := content[e.User]
		if !ok {
			content[e.User] = make(map[string]proto.Message)
			userContent = content[e.User]
		}
		userContent[e.Id] = p
	}
	return nil
}

func (s *DatastoreStorage) ReadHistory(datatype, realm, user, id string, content *[]proto.Message) error {
	return s.ReadHistoryTx(datatype, realm, user, id, content, nil)
}

func (s *DatastoreStorage) ReadHistoryTx(datatype, realm, user, id string, content *[]proto.Message, tx storage.Tx) error {
	if tx == nil {
		var err error
		tx, err = s.Tx(false)
		if err != nil {
			return err
		}
		defer tx.Finish()
	}

	// TODO: handle pagination.
	q := datastore.NewQuery(historyKind).Filter("service =", s.service).Filter("type =", datatype).Filter("realm =", realm).Filter("user_id =", user).Filter("id =", id).Order("rev").Limit(maxPageSize)
	results := make([]DatastoreHistory, maxPageSize)
	if _, err := s.client.GetAll(s.ctx, q, &results); err != nil {
		return err
	}
	for _, e := range results {
		he := new(pb.HistoryEntry)
		if len(e.Content) == 0 {
			continue
		}
		if err := jsonpb.Unmarshal(strings.NewReader(e.Content), he); err != nil {
			return err
		}
		*content = append(*content, he)
	}
	return nil
}

func (s *DatastoreStorage) Write(datatype, realm, user, id string, rev int64, content proto.Message, history proto.Message) error {
	return s.WriteTx(datatype, realm, user, id, rev, content, history, nil)
}

func (s *DatastoreStorage) WriteTx(datatype, realm, user, id string, rev int64, content proto.Message, history proto.Message, tx storage.Tx) error {
	if tx == nil {
		var err error
		tx, err = s.Tx(true)
		if err != nil {
			return err
		}
		defer tx.Finish()
	}
	dstx, ok := tx.(*DatastoreTx)
	if !ok {
		return fmt.Errorf("invalid transaction")
	}

	if rev != storage.LatestRev {
		rk := datastore.NameKey(entityKind, s.entityKey(datatype, realm, user, id, rev), nil)
		re, err := s.datastoreEntity(rk, datatype, realm, user, id, rev, content)
		if err != nil {
			return err
		}
		if _, err = dstx.Tx.Put(rk, re); err != nil {
			dstx.Rollback()
			return err
		}
	}
	if history != nil {
		hk := datastore.NameKey(historyKind, s.historyKey(datatype, realm, user, id, rev), nil)
		he, err := s.datastoreHistory(hk, datatype, realm, user, id, rev, history)
		if err != nil {
			dstx.Rollback()
			return err
		}
		if _, err = dstx.Tx.Put(hk, he); err != nil {
			dstx.Rollback()
			return err
		}
	}
	k := datastore.NameKey(entityKind, s.entityKey(datatype, realm, user, id, storage.LatestRev), nil)
	e, err := s.datastoreEntity(k, datatype, realm, user, id, rev, content)
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

// Delete a record.
func (s *DatastoreStorage) Delete(datatype, realm, user, id string, rev int64) error {
	return s.DeleteTx(datatype, realm, user, id, rev, nil)
}

// DeleteTx delete a record with transaction.
func (s *DatastoreStorage) DeleteTx(datatype, realm, user, id string, rev int64, tx storage.Tx) error {
	if tx == nil {
		var err error
		tx, err = s.Tx(true)
		if err != nil {
			return err
		}
		defer tx.Finish()
	}
	dstx, ok := tx.(*DatastoreTx)
	if !ok {
		return fmt.Errorf("invalid transaction")
	}

	k := datastore.NameKey(entityKind, s.entityKey(datatype, realm, user, id, rev), nil)
	if err := dstx.Tx.Delete(k); err != nil {
		dstx.Rollback()
		return err
	}
	return nil
}

// MultiDeleteTx deletes all records of a certain data type within a realm.
func (s *DatastoreStorage) MultiDeleteTx(datatype, realm, user string, tx storage.Tx) error {
	q := datastore.NewQuery(entityKind).Filter("service =", s.service).Filter("type =", datatype).Filter("realm =", realm)
	if user != storage.DefaultUser {
		q = q.Filter("user_id =", user)
	}
	q = q.Filter("rev = ", storage.LatestRev).Order("id")
	_, err := s.multiDelete(q)
	return err
}

func (s *DatastoreStorage) Wipe(realm string) error {
	glog.Infof("Datastore wipe project %q service %q realm %q: started", s.project, s.service, realm)
	results := make(map[string]int)
	for _, kind := range wipeKinds {
		q := datastore.NewQuery(kind).Filter("service =", s.service)
		if realm != storage.WipeAllRealms {
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

func (s *DatastoreStorage) multiDelete(q *datastore.Query) (int, error) {
	keys, err := s.client.GetAll(s.ctx, q.KeysOnly(), nil)
	if err != nil {
		return 0, err
	}
	total := len(keys)
	for i := 0; i < total; i += multiDeleteChunkSize {
		end := common.Min(i+multiDeleteChunkSize, total)
		chunk := keys[i:end]
		if err := s.client.DeleteMulti(s.ctx, chunk); err != nil {
			return total, err
		}
	}
	return total, nil
}

func (s *DatastoreStorage) Tx(update bool) (storage.Tx, error) {
	var err error
	var dstx *datastore.Transaction
	if update {
		dstx, err = s.client.NewTransaction(s.ctx)
	} else {
		dstx, err = s.client.NewTransaction(s.ctx, datastore.ReadOnly)
	}
	if err != nil {
		return nil, err
	}
	return &DatastoreTx{
		writer: update,
		Tx:     dstx,
	}, nil
}

func (s *DatastoreStorage) init() error {
	k := datastore.NameKey(metaKind, s.metaKey(metaVersion), nil)
	meta := new(DatastoreMeta)
	if err := s.client.Get(s.ctx, k, meta); err == datastore.ErrNoSuchEntity {
		meta = &DatastoreMeta{
			Key:   k,
			Name:  metaVersion,
			Value: storageVersion,
		}
		_, err := s.client.Put(s.ctx, k, meta)
		if err != nil {
			return fmt.Errorf("cannot write datastore metadata: %v", err)
		}
	} else if err != nil {
		return fmt.Errorf("cannot access datastore metadata: %v", err)
	}
	glog.Infof("Datastore service %q version: %s", s.service, meta.Value)
	if meta.Value != storageVersion {
		return fmt.Errorf("datastore version not compatible: expected %q, got %q", storageVersion, meta.Value)
	}
	return nil
}

func (s *DatastoreStorage) entityKey(datatype, realm, user, id string, rev int64) string {
	r := storage.LatestRevName
	if rev > 0 {
		r = fmt.Sprintf("%06d", rev)
	}
	if user == storage.DefaultUser {
		user = "~"
	}
	return fmt.Sprintf("%s/%s/%s/%s/%s/%s", s.service, datatype, realm, user, id, r)
}

func (s *DatastoreStorage) metaKey(id string) string {
	return fmt.Sprintf("%s/%s/%s/%s", s.service, "meta", id, "meta")
}

func (s *DatastoreStorage) historyKey(datatype, realm, user, id string, rev int64) string {
	r := storage.LatestRevName
	if rev > 0 {
		r = fmt.Sprintf("%06d", rev)
	}
	if user == storage.DefaultUser {
		user = "~"
	}
	return fmt.Sprintf("%s/%s.%s/%s/%s/%s/%s", s.service, datatype, storage.HistoryRevName, realm, user, id, r)
}

func (s *DatastoreStorage) datastoreEntity(key *datastore.Key, datatype, realm, user, id string, rev int64, content proto.Message) (*DatastoreEntity, error) {
	m := jsonpb.Marshaler{}
	js, err := m.MarshalToString(content)
	if err != nil {
		return nil, err
	}
	return &DatastoreEntity{
		Key:      key,
		Service:  s.service,
		Datatype: datatype,
		Realm:    realm,
		User:     user,
		Id:       id,
		Rev:      rev,
		Version:  storageVersion,
		Modified: time.Now().Unix(),
		Content:  js,
	}, nil
}

func (s *DatastoreStorage) datastoreHistory(key *datastore.Key, datatype, realm, user, id string, rev int64, content proto.Message) (*DatastoreHistory, error) {
	m := jsonpb.Marshaler{}
	js, err := m.MarshalToString(content)
	if err != nil {
		return nil, err
	}
	return &DatastoreHistory{
		Key:      key,
		Service:  s.service,
		Datatype: datatype,
		Realm:    realm,
		User:     user,
		Id:       id,
		Rev:      rev,
		Version:  storageVersion,
		Modified: time.Now().Unix(),
		Content:  js,
	}, nil
}

type DatastoreTx struct {
	writer bool
	Tx     *datastore.Transaction
}

func (tx *DatastoreTx) Finish() {
	if tx.Tx != nil {
		_, err := tx.Tx.Commit()
		if err != nil {
			glog.Infof("datastore error committing transaction: %v", err)
		}
		tx.Tx = nil
	}
}

func (tx *DatastoreTx) IsUpdate() bool {
	return tx.writer
}

func (tx *DatastoreTx) Rollback() {
	if tx.Tx != nil {
		err := tx.Tx.Rollback()
		if err != nil {
			glog.Infof("datastore error during rollback of transaction: %v", err)
		}
		// Transaction cannot be used after a rollback.
		tx.Tx = nil
	}
}
