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
	"strings"

	"github.com/golang/protobuf/proto"
)

const (
	LatestRev      = int64(-1)
	LatestRevName  = "latest"
	HistoryRevName = "history"
	DefaultRealm   = "master"
	WipeAllRealms  = ""

	AuthCodeDatatype = "auth_code"
	TokensDatatype   = "tokens"
)

type StorageInterface interface {
	Info() map[string]string
	Exists(datatype, realm, id string, rev int64) (bool, error)
	Read(datatype, realm, id string, rev int64, content proto.Message) error
	ReadTx(datatype, realm, id string, rev int64, content proto.Message, tx Tx) error
	MultiReadTx(datatype, realm string, content map[string]proto.Message, typ proto.Message, tx Tx) error
	ReadHistory(datatype, realm, id string, content *[]proto.Message) error
	ReadHistoryTx(datatype, realm, id string, content *[]proto.Message, tx Tx) error
	Write(datatype, realm, id string, rev int64, content proto.Message, history proto.Message) error
	WriteTx(datatype, realm, id string, rev int64, content proto.Message, history proto.Message, tx Tx) error
	Delete(datatype, realm, id string, rev int64) error
	DeleteTx(datatype, realm, id string, rev int64, tx Tx) error
	MultiDeleteTx(datatype, realm string, tx Tx) error
	Wipe(realm string) error
	Tx(update bool) (Tx, error)
}

type Tx interface {
	Finish()
	Rollback()
	IsUpdate() bool
}

func ErrNotFound(err error) bool {
	// TODO(cdvoisin): make this smarter.
	return strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "no such file")
}

// TokensID constructs the ID field for token entities.
func TokensID(sub, id string) string {
	return sub + "/" + id
}
