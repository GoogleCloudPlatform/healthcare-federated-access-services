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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	glog "github.com/golang/glog" /* copybara-comment */
	"github.com/golang/protobuf/jsonpb" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
)

const (
	memStorageType    = "memory"
	memStorageVersion = "v0"
)

// MemoryStorage is designed as a single threading storage. Will throw exception if multiple TX request.
type MemoryStorage struct {
	service   string
	path      string
	pathParts []string
	cache     *StorageCache
	fs        *FileStorage
	deleted   map[string]bool
	lock      chan bool
}

func NewMemoryStorage(service, path string) *MemoryStorage {
	return &MemoryStorage{
		service: service,
		path:    path,
		cache:   NewStorageCache(),
		fs:      NewFileStorage(service, path),
		deleted: make(map[string]bool),
		lock:    make(chan bool, 1),
	}
}

func (m *MemoryStorage) Info() map[string]string {
	return map[string]string{
		"type":    memStorageType,
		"version": memStorageVersion,
		"service": m.service,
		"path":    m.path,
	}
}

func (m *MemoryStorage) Exists(datatype, realm, user, id string, rev int64) (bool, error) {
	fname := m.fname(datatype, realm, user, id, rev)
	if _, ok := m.cache.GetEntity(fname); ok {
		return true, nil
	}
	if m.deleted[fname] {
		return false, nil
	}
	return m.fs.Exists(datatype, realm, user, id, rev)
}

func (m *MemoryStorage) Read(datatype, realm, user, id string, rev int64, content proto.Message) error {
	return m.ReadTx(datatype, realm, user, id, rev, content, nil)
}

func (m *MemoryStorage) ReadTx(datatype, realm, user, id string, rev int64, content proto.Message, tx Tx) error {
	if tx == nil {
		var err error
		tx, err = m.Tx(false)
		if err != nil {
			return err
		}
		defer tx.Finish()
	}

	fname := m.fname(datatype, realm, user, id, rev)
	if data, ok := m.cache.GetEntity(fname); ok {
		content.Reset()
		proto.Merge(content, data)
		return nil
	}

	if m.deleted[fname] {
		return fmt.Errorf("not found: %q", fname)
	}

	if err := m.fs.ReadTx(datatype, realm, user, id, rev, content, tx); err != nil {
		return err
	}

	m.cache.PutEntity(fname, content)
	return nil
}

// MultiReadTx reads a set of objects matching the input parameters and filters
func (m *MemoryStorage) MultiReadTx(datatype, realm, user string, filters []Filter, offset, pageSize int, content map[string]map[string]proto.Message, typ proto.Message, tx Tx) (int, error) {
	if tx == nil {
		var err error
		tx, err = m.fs.Tx(false)
		if err != nil {
			return 0, fmt.Errorf("file read lock error: %v", err)
		}
		defer tx.Finish()
	}

	if pageSize > MaxPageSize {
		pageSize = MaxPageSize
	}
	count := 0
	err := m.findPath(datatype, realm, user, func(path, userMatch, idMatch string) error {
		if m.deleted[m.fname(datatype, realm, userMatch, idMatch, LatestRev)] {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("file %q I/O error: %v", path, err)
		}
		defer file.Close()
		p := proto.Clone(typ)
		if err := jsonpb.Unmarshal(file, p); err != nil && err != io.EOF {
			return fmt.Errorf("file %q invalid JSON: %v", path, err)
		}
		if !MatchProtoFilters(filters, p) {
			return nil
		}
		if offset > 0 {
			offset--
			return nil
		}
		if pageSize > count {
			userContent, ok := content[userMatch]
			if !ok {
				content[userMatch] = make(map[string]proto.Message)
				userContent = content[userMatch]
			}
			userContent[idMatch] = p
		}
		count++
		return nil
	})
	return count, err
}

func (m *MemoryStorage) findPath(datatype, realm, user string, fn func(string, string, string) error) error {
	searchUser := user
	if user == DefaultUser {
		searchUser = "(.*)"
	} else {
		searchUser = "(" + user + ")"
	}
	extractID := m.fs.fname(datatype, realm, searchUser, "(.*)", LatestRev)
	re, err := regexp.Compile(extractID)
	if err != nil {
		return fmt.Errorf("file extract ID %q regexp error: %v", extractID, err)
	}
	defaultUserID := m.fs.fname(datatype, realm, DefaultUser, "(.*)", LatestRev)
	dure, err := regexp.Compile(defaultUserID)
	if err != nil {
		return fmt.Errorf("file extract ID %q regexp error: %v", defaultUserID, err)
	}
	return filepath.Walk(m.fs.path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		matches := re.FindStringSubmatch(path)
		var userMatch string
		var idMatch string
		if len(matches) == 3 {
			userMatch = matches[1]
			idMatch = matches[2]
		} else if user == DefaultUser {
			matches = dure.FindStringSubmatch(path)
			if len(matches) == 2 {
				userMatch = "default"
				idMatch = matches[1]
			} else {
				return nil
			}
		} else {
			return nil
		}
		return fn(path, userMatch, idMatch)
	})
}

func (m *MemoryStorage) ReadHistory(datatype, realm, user, id string, content *[]proto.Message) error {
	return m.ReadHistoryTx(datatype, realm, user, id, content, nil)
}

func (m *MemoryStorage) ReadHistoryTx(datatype, realm, user, id string, content *[]proto.Message, tx Tx) error {
	if tx == nil {
		var err error
		tx, err = m.Tx(false)
		if err != nil {
			return err
		}
		defer tx.Finish()
	}

	hfname := m.historyName(datatype, realm, user, id)
	if data, ok := m.cache.GetHistory(hfname); ok {
		for _, he := range data {
			*content = append(*content, he)
		}
		return nil
	}

	if err := m.fs.ReadHistoryTx(datatype, realm, user, id, content, tx); err != nil {
		return err
	}

	m.cache.PutHistory(hfname, *content)
	return nil
}

func (m *MemoryStorage) Write(datatype, realm, user, id string, rev int64, content proto.Message, history proto.Message) error {
	return m.WriteTx(datatype, realm, user, id, rev, content, history, nil)
}

func (m *MemoryStorage) WriteTx(datatype, realm, user, id string, rev int64, content proto.Message, history proto.Message, tx Tx) error {
	if tx == nil {
		var err error
		tx, err = m.Tx(true)
		if err != nil {
			return err
		}
		defer tx.Finish()
	}

	hlist := make([]proto.Message, 0)
	if err := m.ReadHistoryTx(datatype, realm, user, id, &hlist, tx); err != nil && !ErrNotFound(err) {
		return err
	}

	hlist = append(hlist, history)
	hfname := m.historyName(datatype, realm, user, id)
	m.cache.PutHistory(hfname, hlist)

	vname := m.fname(datatype, realm, user, id, rev)
	m.cache.PutEntity(vname, content)
	lname := m.fname(datatype, realm, user, id, LatestRev)
	m.cache.PutEntity(lname, content)
	if _, ok := m.deleted[vname]; ok {
		delete(m.deleted, vname)
	}
	if _, ok := m.deleted[lname]; ok {
		delete(m.deleted, lname)
	}

	return nil
}

// Delete a record.
func (m *MemoryStorage) Delete(datatype, realm, user, id string, rev int64) error {
	return m.DeleteTx(datatype, realm, user, id, rev, nil)
}

// DeleteTx delete a record with transaction.
func (m *MemoryStorage) DeleteTx(datatype, realm, user, id string, rev int64, tx Tx) error {
	if tx == nil {
		var err error
		tx, err = m.Tx(true)
		if err != nil {
			return err
		}
		defer tx.Finish()
	}
	vname := m.fname(datatype, realm, user, id, rev)
	m.cache.DeleteEntity(vname)
	lname := m.fname(datatype, realm, user, id, LatestRev)
	m.cache.DeleteEntity(lname)
	m.deleted[vname] = true
	m.deleted[lname] = true
	return nil
}

// MultiDeleteTx deletes all records of a certain data type within a realm.
func (m *MemoryStorage) MultiDeleteTx(datatype, realm, user string, tx Tx) error {
	if tx == nil {
		var err error
		tx, err = m.fs.Tx(false)
		if err != nil {
			return fmt.Errorf("file read lock error: %v", err)
		}
		defer tx.Finish()
	}

	return m.findPath(datatype, realm, user, func(path, userMatch, idMatch string) error {
		return m.DeleteTx(datatype, realm, userMatch, idMatch, LatestRev, tx)
	})
}

func (m *MemoryStorage) Wipe(realm string) error {
	// Wipe everything, not just for the realm provided.
	m.cache = NewStorageCache()
	m.deleted = make(map[string]bool)
	return nil
}

func (m *MemoryStorage) Tx(update bool) (Tx, error) {
	select {
	case m.lock <- true:
	default:
		panic("MAYBE BUG: Requested a new TX without the existing TX release.")
	}
	m.cache.Backup()
	return &MemTx{
		update: update,
		ms:     m,
	}, nil
}

type MemTx struct {
	update bool
	ms     *MemoryStorage
}

func (tx *MemTx) Finish() {
	select {
	case <-tx.ms.lock:
	default:
		panic("MAYBE BUG: Releasing a released TX.")
	}
}

func (tx *MemTx) Rollback() {
	tx.ms.cache.Restore()
	tx.ms.fs = NewFileStorage(tx.ms.service, tx.ms.path)
}

func (tx *MemTx) IsUpdate() bool {
	return tx.update
}

func (m *MemoryStorage) fname(datatype, realm, user, id string, rev int64) string {
	r := LatestRevName
	if rev > 0 {
		r = fmt.Sprintf("%06d", rev)
	}
	name := fmt.Sprintf("%s_%s%s_%s_%s.json", datatype, realm, UserFragment(user), id, r)
	p := filepath.Join(m.path, m.service, name)
	glog.Infof("p=%q", p)
	return p
}

func (m *MemoryStorage) historyName(datatype, realm, user, id string) string {
	name := fmt.Sprintf("%s_%s%s_%s_%s.json", datatype, realm, UserFragment(user), id, HistoryRevName)
	p := filepath.Join(m.path, m.service, name)
	glog.Infof("p=%q", p)
	return p
}
