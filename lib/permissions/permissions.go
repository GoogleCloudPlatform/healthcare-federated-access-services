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

// Package permissions contains codes share between IC and DAM.
package permissions

import (
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	glog "github.com/golang/glog" /* copybara-comment */
	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
)

const cacheTimeout = time.Minute * 5

// Permissions type exposes functions access user permissions.
type Permissions struct {
	store             storage.Store
	cachedPermissions *cpb.Permissions
	cacheExpiry       time.Time
	mutex             sync.Mutex
}

// New creates Permissions.
func New(store storage.Store) *Permissions {
	return &Permissions{store: store}
}

// loadPermissions loads permission from storage/config.
func (p *Permissions) loadPermissions() (*cpb.Permissions, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	now := time.Now()
	// return if valid cached value available
	if p.cachedPermissions != nil && p.cacheExpiry.After(now) {
		return p.cachedPermissions, nil
	}

	p.cacheExpiry = now.Add(cacheTimeout)
	p.cachedPermissions = &cpb.Permissions{}
	if err := p.store.Read(storage.PermissionsDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, p.cachedPermissions); err != nil {
		return nil, err
	}
	return p.cachedPermissions, nil
}

// CheckAdmin returns if user has valid admin permission.
func (p *Permissions) CheckAdmin(id *ga4gh.Identity) (bool, error) {
	perm, err := p.loadPermissions()
	if err != nil {
		return false, err
	}
	return isAdmin(perm, id), nil
}

func extractIdentitiesFromVisas(id *ga4gh.Identity) []string {
	var subjects []string

	for _, j := range id.VisaJWTs {
		v, err := ga4gh.NewVisaFromJWT(ga4gh.VisaJWT(j))
		if err != nil {
			glog.Warningf("ga4gh.NewVisaFromJWT failed: %v", err)
			continue
		}

		if v.Data().Assertion.Type != ga4gh.LinkedIdentities {
			continue
		}

		// TODO Need to verify JWT before use.
		// TODO Need to verify JWT from trust issuer and source.

		subjects = append(subjects, v.Data().Subject)
		for _, s := range strings.Split(string(v.Data().Assertion.Value), ";") {
			ss := strings.Split(s, ",")
			if len(ss) != 2 {
				glog.Warning("LinkedIdentities in wrong format")
				continue
			}

			email, err := url.QueryUnescape(ss[0])
			if err != nil {
				glog.Warningf("url.QueryUnescape(email) failed: %v", err)
				continue
			}
			subjects = append(subjects, email)
		}
	}

	return subjects
}

// isAdmin returns true if the identity's underlying account has
// administrative privileges without checking scopes or other
// restrictions related to the auth token itself.
func isAdmin(perm *cpb.Permissions, id *ga4gh.Identity) bool {
	if id == nil {
		return false
	}
	now := time.Now()
	if isAdminUser(perm, id.Subject, now) {
		return true
	}
	for user := range id.Identities {
		if isAdminUser(perm, user, now) {
			return true
		}
	}

	for _, sub := range extractIdentitiesFromVisas(id) {
		if isAdminUser(perm, sub, now) {
			return true
		}
	}

	return false
}

func isAdminUser(perm *cpb.Permissions, user string, now time.Time) bool {
	// Only allowing "sub" that contain an "@" symbol. We don't want
	// to allow admins to try to trigger on a raw account number
	// without knowing where it came from.
	if !strings.Contains(user, "@") {
		return false
	}
	u, ok := perm.Users[user]
	if !ok {
		return false
	}
	r, ok := u.Roles["admin"]
	if ok && (r < 0 || r > now.UnixNano()/1e9) {
		return true
	}
	return false
}
