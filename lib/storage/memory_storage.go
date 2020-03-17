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
	"time"

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
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
	lastLock  time.Time
}

func NewMemoryStorage(service, path string) *MemoryStorage {
	return &MemoryStorage{
		service:  service,
		path:     path,
		cache:    NewStorageCache(),
		fs:       NewFileStorage(service, path),
		deleted:  make(map[string]bool),
		lock:     make(chan bool, 1),
		lastLock: time.Unix(0, 0),
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

// ReadTx reads inside a transaction.
func (m *MemoryStorage) ReadTx(datatype, realm, user, id string, rev int64, content proto.Message, tx Tx) (ferr error) {
	if tx == nil {
		var err error
		tx, err = m.Tx(false)
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
func (m *MemoryStorage) MultiReadTx(datatype, realm, user string, filters [][]Filter, offset, pageSize int, content map[string]map[string]proto.Message, typ proto.Message, tx Tx) (_ int, ferr error) {
	if tx == nil {
		var err error
		tx, err = m.fs.Tx(false)
		if err != nil {
			return 0, fmt.Errorf("file read lock error: %v", err)
		}
		defer func() {
			err := tx.Finish()
			if ferr == nil {
				ferr = err
			}
		}()
	}

	if pageSize > MaxPageSize {
		pageSize = MaxPageSize
	}
	count := 0
	err := m.findPath(datatype, realm, user, typ, func(path, userMatch, idMatch string, p proto.Message) error {
		if m.deleted[m.fname(datatype, realm, userMatch, idMatch, LatestRev)] {
			return nil
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

func (m *MemoryStorage) findPath(datatype, realm, user string, typ proto.Message, fn func(string, string, string, proto.Message) error) error {
	searchUser := user
	if user == DefaultUser {
		searchUser = "(.*)"
	} else {
		searchUser = "(" + user + ")"
	}
	searchRealm := realm
	if realm == AllRealms {
		searchRealm = "(.*)"
	}
	extractID := m.fs.fname(datatype, searchRealm, searchUser, "(.*)", LatestRev)
	re, err := regexp.Compile(extractID)
	if err != nil {
		return fmt.Errorf("file extract ID %q regexp error: %v", extractID, err)
	}
	defaultUserID := m.fs.fname(datatype, realm, DefaultUser, "(.*)", LatestRev)
	dure, err := regexp.Compile(defaultUserID)
	if err != nil {
		return fmt.Errorf("file extract ID %q regexp error: %v", defaultUserID, err)
	}
	cached := m.cache.Entities()
	fileMatcher := func(path string, info os.FileInfo, err error) error {
		return extractFromPath(re, dure, user, path, info, err, typ, cached, fn)
	}
	if err = filepath.Walk(m.fs.path, fileMatcher); err != nil {
		return err
	}
	return extractFromCache(re, dure, user, cached, fn)
}

func extractFromPath(re, dure *regexp.Regexp, user, path string, info os.FileInfo, err error, typ proto.Message, cached map[string]proto.Message, fn func(string, string, string, proto.Message) error) error {
	if err != nil {
		return err
	}
	if info.IsDir() {
		return nil
	}
	if _, ok := cached[path]; ok {
		return nil
	}
	userMatch, idMatch := extractUserAndID(re, dure, user, path)
	if userMatch == "" && idMatch == "" {
		return nil
	}
	var p proto.Message
	if typ != nil {
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("file %q I/O error: %v", path, err)
		}
		defer file.Close()
		p = proto.Clone(typ)
		if err := jsonpb.Unmarshal(file, p); err != nil && err != io.EOF {
			return fmt.Errorf("file %q invalid JSON: %v", path, err)
		}
	}
	return fn(path, userMatch, idMatch, p)
}

func extractUserAndID(re, dure *regexp.Regexp, user, path string) (string, string) {
	matches := re.FindStringSubmatch(path)
	if len(matches) == 3 {
		return matches[1], matches[2]
	}
	if user == DefaultUser {
		matches = dure.FindStringSubmatch(path)
		if len(matches) == 2 {
			return DefaultUser, matches[1]
		}
	}
	return "", ""
}

func extractFromCache(re, dure *regexp.Regexp, user string, cached map[string]proto.Message, fn func(string, string, string, proto.Message) error) error {
	for path, content := range cached {
		if !re.MatchString(path) && !dure.MatchString(path) {
			continue
		}
		userMatch, idMatch := extractUserAndID(re, dure, user, path)
		if userMatch == "" && idMatch == "" {
			continue
		}
		if err := fn(path, userMatch, idMatch, content); err != nil {
			return err
		}
	}
	return nil
}

func (m *MemoryStorage) ReadHistory(datatype, realm, user, id string, content *[]proto.Message) error {
	return m.ReadHistoryTx(datatype, realm, user, id, content, nil)
}

// ReadHistoryTx reads history inside a transaction.
func (m *MemoryStorage) ReadHistoryTx(datatype, realm, user, id string, content *[]proto.Message, tx Tx) (ferr error) {
	if tx == nil {
		var err error
		tx, err = m.Tx(false)
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

// WriteTx writes inside a transaction.
func (m *MemoryStorage) WriteTx(datatype, realm, user, id string, rev int64, content proto.Message, history proto.Message, tx Tx) (ferr error) {
	if tx == nil {
		var err error
		tx, err = m.Tx(true)
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
func (m *MemoryStorage) DeleteTx(datatype, realm, user, id string, rev int64, tx Tx) (ferr error) {
	if tx == nil {
		var err error
		tx, err = m.Tx(true)
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
	exists, err := m.Exists(datatype, realm, user, id, rev)
	if err != nil {
		return err
	}
	lname := m.fname(datatype, realm, user, id, LatestRev)
	if !exists {
		return status.Errorf(codes.NotFound, "not found: %q", lname)
	}
	vname := m.fname(datatype, realm, user, id, rev)
	m.cache.DeleteEntity(vname)
	m.cache.DeleteEntity(lname)
	m.deleted[vname] = true
	m.deleted[lname] = true
	return nil
}

// MultiDeleteTx deletes all records of a certain data type within a realm.
func (m *MemoryStorage) MultiDeleteTx(datatype, realm, user string, tx Tx) (ferr error) {
	if tx == nil {
		var err error
		tx, err = m.fs.Tx(false)
		if err != nil {
			return fmt.Errorf("file read lock error: %v", err)
		}
		defer func() {
			err := tx.Finish()
			if ferr == nil {
				ferr = err
			}
		}()
	}

	return m.findPath(datatype, realm, user, nil, func(path, userMatch, idMatch string, p proto.Message) error {
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

// LockTx returns a storage-wide lock by the given name. Only one such lock should
// be requested at a time. If Tx is provided, it must be an update Tx.
func (m *MemoryStorage) LockTx(lockName string, minFrequency time.Duration, tx Tx) Tx {
	now := time.Now()
	if now.Sub(m.lastLock) < minFrequency {
		return nil
	}
	if tx == nil {
		var err error
		tx, err = m.Tx(true)
		if err != nil {
			return nil
		}
	}
	m.lastLock = now
	return tx
}

type MemTx struct {
	update bool
	ms     *MemoryStorage
}

// Finish attempts to commit a transaction.
func (tx *MemTx) Finish() error {
	select {
	case <-tx.ms.lock:
	default:
		panic("MAYBE BUG: Releasing a released TX.")
	}
	return nil
}

// Rollback attempts to rollback a transaction.
func (tx *MemTx) Rollback() error {
	tx.ms.cache.Restore()
	tx.ms.fs = NewFileStorage(tx.ms.service, tx.ms.path)
	return nil
}

// MakeUpdate will upgrade a read-only transaction to an update transaction.
func (tx *MemTx) MakeUpdate() error {
	tx.update = true
	return nil
}

func (tx *MemTx) IsUpdate() bool {
	return tx.update
}

func (m *MemoryStorage) fname(datatype, realm, user, id string, rev int64) string {
	return m.fs.fname(datatype, realm, user, id, rev)
}

func (m *MemoryStorage) historyName(datatype, realm, user, id string) string {
	return m.fs.historyName(datatype, realm, user, id)
}
