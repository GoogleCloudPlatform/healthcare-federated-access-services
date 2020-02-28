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
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	glog "github.com/golang/glog" /* copybara-comment */
	"github.com/golang/protobuf/jsonpb" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/srcutil" /* copybara-comment: srcutil */
	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
)

const (
	storageType    = "file"
	storageVersion = "v0"
)

type FileStorage struct {
	service string
	path    string
	mu      sync.Mutex
	cache   *StorageCache
}

func NewFileStorage(service, path string) *FileStorage {
	// Add the service name directory to the path:
	// 1. Add the full service name if the subdirectory exists; or
	// 2. The base service name (i.e. before the first "-" character).
	servicePath := srcutil.Path(filepath.Join(path, service))
	if err := checkFile(servicePath); err == nil {
		path = servicePath
	} else {
		path = srcutil.Path(filepath.Join(path, strings.Split(service, "-")[0]))
	}

	glog.Infof("file storage for service %q using path %q.", service, path)
	f := &FileStorage{
		service: strings.Split(service, "-")[0],
		path:    path,
		cache:   NewStorageCache(),
	}

	return f
}

func (f *FileStorage) Info() map[string]string {
	return map[string]string{
		"type":    storageType,
		"version": storageVersion,
		"service": f.service,
		"path":    f.path,
	}
}

func (f *FileStorage) Exists(datatype, realm, user, id string, rev int64) (bool, error) {
	fn := f.fname(datatype, realm, user, id, rev)
	if _, ok := f.cache.GetEntity(fn); ok {
		return true, nil
	}
	err := checkFile(fn)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func (f *FileStorage) Read(datatype, realm, user, id string, rev int64, content proto.Message) error {
	return f.ReadTx(datatype, realm, user, id, rev, content, nil)
}

func (f *FileStorage) ReadTx(datatype, realm, user, id string, rev int64, content proto.Message, tx Tx) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	fname := f.fname(datatype, realm, user, id, rev)
	if tx == nil || !tx.IsUpdate() {
		if data, ok := f.cache.GetEntity(fname); ok {
			content.Reset()
			proto.Merge(content, data)
			return nil
		}
	}

	if tx == nil {
		var err error
		tx, err = f.Tx(false)
		if err != nil {
			return fmt.Errorf("file read lock error: %v", err)
		}
		defer tx.Finish()
	}

	if err := checkFile(fname); err != nil {
		return err
	}
	file, err := os.Open(fname)
	if err != nil {
		return fmt.Errorf("file %q I/O error: %v", fname, err)
	}
	defer file.Close()
	if err := jsonpb.Unmarshal(file, content); err != nil && err != io.EOF {
		return fmt.Errorf("file %q invalid JSON: %v", fname, err)
	}
	if rev == LatestRev {
		f.cache.PutEntity(fname, content)
	}
	return nil
}

// MultiReadTx reads a set of objects matching the input parameters and filters
func (f *FileStorage) MultiReadTx(datatype, realm, user string, filters [][]Filter, offset, pageSize int, content map[string]map[string]proto.Message, typ proto.Message, tx Tx) (int, error) {
	return 0, fmt.Errorf("file storage does not support MultiReadTx")
}

func (f *FileStorage) ReadHistory(datatype, realm, user, id string, content *[]proto.Message) error {
	return f.ReadHistoryTx(datatype, realm, user, id, content, nil)
}

func (f *FileStorage) ReadHistoryTx(datatype, realm, user, id string, content *[]proto.Message, tx Tx) error {
	if tx == nil {
		var err error
		tx, err = f.Tx(false)
		if err != nil {
			return fmt.Errorf("history file read lock error: %v", err)
		}
		defer tx.Finish()
	}

	hfname := f.historyName(datatype, realm, user, id)
	if err := checkFile(hfname); err != nil {
		return err
	}
	b, err := ioutil.ReadFile(hfname)
	if err != nil {
		return fmt.Errorf("history file %q I/O error: %v", hfname, err)
	}
	full := `{"history":[` + string(b[:]) + "]}"
	his := &cpb.History{}
	if err := jsonpb.Unmarshal(strings.NewReader(full), his); err != nil {
		return fmt.Errorf("history file %q invalid JSON: %v", hfname, err)
	}
	for _, he := range his.History {
		*content = append(*content, proto.Message(he))
	}
	f.cache.PutHistory(hfname, *content)
	return nil
}

func (f *FileStorage) Write(datatype, realm, user, id string, rev int64, content proto.Message, history proto.Message) error {
	return fmt.Errorf("file storage does not support Write")
}

func (f *FileStorage) WriteTx(datatype, realm, user, id string, rev int64, content proto.Message, history proto.Message, tx Tx) error {
	return fmt.Errorf("file storage does not support WriteTx")
}

// Delete a record.
func (f *FileStorage) Delete(datatype, realm, user, id string, rev int64) error {
	return fmt.Errorf("file storage does not support Delete")
}

// DeleteTx delete a record with transaction.
func (f *FileStorage) DeleteTx(datatype, realm, user, id string, rev int64, tx Tx) error {
	return fmt.Errorf("file storage does not support DeleteTx")
}

// MultiDeleteTx deletes all records of a certain data type within a realm.
func (f *FileStorage) MultiDeleteTx(datatype, realm, user string, tx Tx) error {
	return fmt.Errorf("file storage does not support MultiDeleteTx")
}

// Wipe deletes all records within a realm.
func (f *FileStorage) Wipe(realm string) error {
	return fmt.Errorf("file storage does not support Wipe")
}

func (f *FileStorage) Tx(update bool) (Tx, error) {
	return &FileTx{
		writer: update,
	}, nil
}

// LockTx returns a storage-wide lock by the given name. Only one such lock should
// be requested at a time. If Tx is provided, it must be an update Tx.
func (f *FileStorage) LockTx(lockName string, minFrequency time.Duration, tx Tx) Tx {
	// Filestore does not support writing transactions, and returning nil indicates that
	// the lock is not acquired.
	return nil
}

type FileTx struct {
	writer bool
}

// Finish attempts to commit a transaction.
func (tx *FileTx) Finish() error {
	return nil
}

// Rollback attempts to rollback a transaction.
func (tx *FileTx) Rollback() error {
	return nil
}

func (tx *FileTx) IsUpdate() bool {
	return tx.writer
}

func UserFragment(user string) string {
	if user == DefaultUser {
		return ""
	}
	return "_" + user
}
