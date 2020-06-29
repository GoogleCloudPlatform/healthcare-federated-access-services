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

// Package scim implements a SCIM-like interface for group and user management.
package scim

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	spb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/scim/v2" /* copybara-comment: go_proto */
)

const (
	scimGroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimListSchema  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimPatchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	scimUserSchema  = "urn:ietf:params:scim:schemas:core:2.0:User"
)

// Scim is a System for Cross-domain Identity Management.
// It bridges the internal account representation with an externally
// facing API based on the SCIM v2 standard.
type Scim struct {
	store storage.Store
}

// New creates a new SCIM.
func New(store storage.Store) *Scim {
	return &Scim{
		store: store,
	}
}

// LoadAccount loads one internal account from storage. It will filter disabled or deleted accounts unless
// `anyState` is set to true.
func (s *Scim) LoadAccount(name, realm string, anyState bool, tx storage.Tx) (*cpb.Account, int, error) {
	acct := &cpb.Account{}
	status, err := s.readTx(storage.AccountDatatype, realm, storage.DefaultUser, name, storage.LatestRev, acct, tx)
	if err != nil {
		return nil, status, err
	}
	// TODO: move state checks to storage package.
	if acct.State != storage.StateActive && !anyState {
		return nil, http.StatusNotFound, fmt.Errorf("not found")
	}
	return acct, http.StatusOK, nil
}

// LookupAccount loads one internal account based on supplying a federated account identitifer such as an email address.
// It will filter disabled or deleted accounts unless `anyState` is set to true.
func (s *Scim) LookupAccount(fedAcct, realm string, anyState bool, tx storage.Tx) (*cpb.Account, int, error) {
	lookup, err := s.LoadAccountLookup(realm, fedAcct, tx)
	if err != nil {
		return nil, http.StatusServiceUnavailable, err
	}
	if lookup == nil {
		return nil, http.StatusNotFound, fmt.Errorf("subject not found")
	}
	return s.LoadAccount(lookup.Subject, realm, anyState, tx)
}

// LoadAccountLookup loads an account reference structure (AccountLookup) that points an federated account identifier
// such as an email address with where the account is stored internally. Note that multiple external identifiers
// or emails can map to one internal account (i.e. account linking).
func (s *Scim) LoadAccountLookup(realm, acct string, tx storage.Tx) (*cpb.AccountLookup, error) {
	lookup := &cpb.AccountLookup{}
	status, err := s.readTx(storage.AccountLookupDatatype, realm, storage.DefaultUser, acct, storage.LatestRev, lookup, tx)
	if err != nil && status == http.StatusNotFound {
		return nil, nil
	}
	return lookup, err
}

// SaveAccountLookup puts an account lookup reference structure in storage.
func (s *Scim) SaveAccountLookup(lookup *cpb.AccountLookup, realm, fedAcct string, r *http.Request, id *ga4gh.Identity, tx storage.Tx) error {
	lookup.Revision++
	lookup.CommitTime = float64(time.Now().UnixNano()) / 1e9
	if err := s.store.WriteTx(storage.AccountLookupDatatype, realm, storage.DefaultUser, fedAcct, lookup.Revision, lookup, storage.MakeConfigHistory("link account", storage.AccountLookupDatatype, lookup.Revision, lookup.CommitTime, r, id.Subject, nil, lookup), tx); err != nil {
		return fmt.Errorf("service storage unavailable: %v, retry later", err)
	}
	return nil
}

// RemoveAccountLookup removes an account lookup reference structure from storage by marking it as DELETED.
// Providence is maintained by not fully deleting the data.
func (s *Scim) RemoveAccountLookup(rev int64, realm, fedAcct string, r *http.Request, id *ga4gh.Identity, tx storage.Tx) error {
	lookup := &cpb.AccountLookup{
		Subject:  "",
		Revision: rev,
		State:    "DELETED",
	}
	if err := s.SaveAccountLookup(lookup, realm, fedAcct, r, id, tx); err != nil {
		return err
	}
	return nil
}

// SaveAccount puts an internal account structure in storage.
func (s *Scim) SaveAccount(oldAcct, newAcct *cpb.Account, desc, subject, realm string, r *http.Request, tx storage.Tx) error {
	newAcct.Revision++
	newAcct.Properties.Modified = float64(time.Now().UnixNano()) / 1e9
	if newAcct.Properties.Created == 0 {
		if oldAcct != nil && oldAcct.Properties.Created != 0 {
			newAcct.Properties.Created = oldAcct.Properties.Created
		} else {
			newAcct.Properties.Created = newAcct.Properties.Modified
		}
	}

	if err := s.store.WriteTx(storage.AccountDatatype, realm, storage.DefaultUser, newAcct.Properties.Subject, newAcct.Revision, newAcct, storage.MakeConfigHistory(desc, storage.AccountDatatype, newAcct.Revision, newAcct.Properties.Modified, r, subject, oldAcct, newAcct), tx); err != nil {
		return fmt.Errorf("service storage unavailable: %v, retry later", err)
	}
	return nil
}

// LoadGroup loads a user group.
func (s *Scim) LoadGroup(name, realm string, tx storage.Tx) (*spb.Group, error) {
	group := &spb.Group{}
	st, err := s.readTx(storage.GroupDatatype, realm, name, storage.DefaultID, storage.LatestRev, group, tx)
	if err != nil {
		if st == http.StatusNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("loading group %q failed: %v", name, err)
	}
	return group, nil
}

// LoadGroupMember loads a user membership record as part of a group.
func (s *Scim) LoadGroupMember(groupName, memberName, realm string, tx storage.Tx) (*spb.Member, error) {
	member := &spb.Member{}
	st, err := s.readTx(storage.GroupMemberDatatype, realm, groupName, memberName, storage.LatestRev, member, tx)
	if err != nil {
		if st == http.StatusNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("loading group %q member %q failed: %v", groupName, memberName, err)
	}
	return member, nil
}

func (s *Scim) readTx(datatype, realm, user, id string, rev int64, item proto.Message, tx storage.Tx) (int, error) {
	err := s.store.ReadTx(datatype, realm, user, id, rev, item, tx)
	if err == nil {
		return http.StatusOK, nil
	}
	if storage.ErrNotFound(err) {
		if len(id) > 0 && id != storage.DefaultID {
			return http.StatusNotFound, fmt.Errorf("%s %q not found", datatype, id)
		}
		return http.StatusNotFound, fmt.Errorf("%s not found", datatype)
	}
	return http.StatusServiceUnavailable, fmt.Errorf("service storage unavailable: %v, retry later", err)
}

func getRealm(r *http.Request) string {
	if r == nil {
		return storage.DefaultRealm
	}
	if realm, ok := mux.Vars(r)["realm"]; ok && len(realm) > 0 {
		return realm
	}
	return storage.DefaultRealm
}
