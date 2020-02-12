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

package clouds

import (
	"context"
	"time"
)

// Account represents a user or service account within the underlying system.
type Account struct {
	ID          string
	DisplayName string
	Description string
}

// AccountManager abstracts account management within a target cloud environment.
type AccountManager interface {

	// GetServiceAccounts calls "callback" once per service account for the given project.
	GetServiceAccounts(ctx context.Context, project string, callback func(sa *Account) bool) error

	// RemoveServiceAccount removes a service account related to the given project.
	RemoveServiceAccount(ctx context.Context, project, accountID string) error

	// ManageAccountKeys maintains or removes keys on a clean-up cycle. Returns: remaining keys for account, removed keys for account, and error.
	ManageAccountKeys(ctx context.Context, project, accountID string, ttl, maxKeyTTL time.Duration, keysPerAccount int) (int, int, error)
}
