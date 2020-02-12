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

// MockAccountManagerEntry represents a call to an account management endpoint
type MockAccountManagerEntry struct {
	Call           string
	AccountID      string
	Project        string
	TTL            time.Duration
	MaxKeyTTL      time.Duration
	KeysPerAccount int
}

// MockAccountManager provides an account manager implementation for testing.
type MockAccountManager struct {
	accounts []*Account
	calls    []MockAccountManagerEntry
}

// NewMockAccountManager creates a mock AccountManager.
func NewMockAccountManager(accounts []*Account) *MockAccountManager {
	return &MockAccountManager{
		accounts: accounts,
		calls:    []MockAccountManagerEntry{},
	}
}

// GetServiceAccounts calls "callback" once per service account for the given project.
func (m *MockAccountManager) GetServiceAccounts(ctx context.Context, project string, callback func(sa *Account) bool) error {
	m.calls = append(m.calls, MockAccountManagerEntry{Call: "GetServiceAccounts", Project: project})
	for _, account := range m.accounts {
		if callback(account) == false {
			break
		}
	}
	return nil
}

// RemoveServiceAccount removes a service account related to the given project.
func (m *MockAccountManager) RemoveServiceAccount(ctx context.Context, project, accountID string) error {
	m.calls = append(m.calls, MockAccountManagerEntry{Call: "RemoveServiceAccount", Project: project, AccountID: accountID})
	return nil
}

// ManageAccountKeys maintains or removes keys on a clean-up cycle. Returns: remaining keys for account, removed keys for account, and error.
func (m *MockAccountManager) ManageAccountKeys(ctx context.Context, project, accountID string, ttl, maxKeyTTL time.Duration, keysPerAccount int) (int, int, error) {
	m.calls = append(m.calls, MockAccountManagerEntry{Call: "ManageAccountKeys", Project: project, AccountID: accountID, TTL: ttl, MaxKeyTTL: maxKeyTTL, KeysPerAccount: keysPerAccount})
	return 1, 2, nil
}
