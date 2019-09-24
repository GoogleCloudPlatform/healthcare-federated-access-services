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
	DefaultUser    = ""
	DefaultID      = "main"
	WipeAllRealms  = ""

	AccountDatatype        = "account"
	AccountLookupDatatype  = "acct_lookup"
	AuthCodeDatatype       = "auth_code"
	ClientDatatype         = "client"
	ConfigDatatype         = "config"
	LoginStateDatatype     = "login_state"
	AuthTokenStateDatatype = "auth_token_state"
	PermissionsDatatype    = "permissions"
	SecretsDatatype        = "secrets"
	TokensDatatype         = "tokens"

	ResourceTokenRequestStateDataType = "resource_token_state"
)

// Store is an interface to the storage layer.
type Store interface {
	Info() map[string]string
	Exists(datatype, realm, user, id string, rev int64) (bool, error)
	Read(datatype, realm, user, id string, rev int64, content proto.Message) error
	ReadTx(datatype, realm, user, id string, rev int64, content proto.Message, tx Tx) error
	MultiReadTx(datatype, realm, user string, content map[string]map[string]proto.Message, typ proto.Message, tx Tx) error
	ReadHistory(datatype, realm, user, id string, content *[]proto.Message) error
	ReadHistoryTx(datatype, realm, user, id string, content *[]proto.Message, tx Tx) error
	Write(datatype, realm, user, id string, rev int64, content proto.Message, history proto.Message) error
	WriteTx(datatype, realm, user, id string, rev int64, content proto.Message, history proto.Message, tx Tx) error
	Delete(datatype, realm, user, id string, rev int64) error
	DeleteTx(datatype, realm, user, id string, rev int64, tx Tx) error
	MultiDeleteTx(datatype, realm, user string, tx Tx) error
	Wipe(realm string) error
	Tx(update bool) (Tx, error)
}

type Tx interface {
	Finish()
	Rollback()
	IsUpdate() bool
}

func ErrNotFound(err error) bool {
	// TODO: make this smarter.
	return strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "no such file")
}
