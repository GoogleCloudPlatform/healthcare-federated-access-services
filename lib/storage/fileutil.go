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

// Package storage provides storage for IC and DAM.
package storage

import (
	"fmt"
	"os"
	"path/filepath"

	glog "github.com/golang/glog" /* copybara-comment */
)

func checkFile(path string) error {
	_, err := os.Stat(path)
	if err != nil {
		glog.Errorf("os.Stat(%v) = %v", path, err)
	}
	return err
}

func (f *FileStorage) fname(datatype, realm, user, id string, rev int64) string {
	r := LatestRevName
	if rev > 0 {
		r = fmt.Sprintf("%06d", rev)
	}
	name := fmt.Sprintf("%s_%s%s_%s_%s.json", datatype, realm, UserFragment(user), id, r)
	return filepath.Join(f.path, name)
}

func (f *FileStorage) historyName(datatype, realm, user, id string) string {
	name := fmt.Sprintf("%s_%s%s_%s_%s.json", datatype, realm, UserFragment(user), id, HistoryRevName)
	return filepath.Join(f.path, name)
}
