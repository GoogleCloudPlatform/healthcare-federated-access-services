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
	"fmt"
	"time"
)

type MockTokenCreatorEntry struct {
	ID      string
	TTL     time.Duration
	MaxTTL  time.Duration
	NumKeys int
	Params  ResourceTokenCreationParams
}

type mockTokenCreator struct {
	includeParams bool
	calls         []MockTokenCreatorEntry
}

// NewMockTokenCreator creates a mock ResourceTokenCreator.
func NewMockTokenCreator(includeParams bool) *mockTokenCreator {
	return &mockTokenCreator{
		includeParams: includeParams,
		calls:         []MockTokenCreatorEntry{},
	}
}

// RegisterAccountProject registers account hosting project in key garbage collector.
func (m *mockTokenCreator) RegisterAccountProject(realm, project string, maxRequestedTTL int, keysPerAccount int) error {
	return nil
}

// GetTokenWithTTL returns an account and a resource token for resource accessing.
func (m *mockTokenCreator) GetTokenWithTTL(ctx context.Context, id string, ttl, maxTTL time.Duration, numKeys int, params *ResourceTokenCreationParams) (string, string, error) {
	entry := MockTokenCreatorEntry{
		ID:      id,
		TTL:     ttl,
		MaxTTL:  maxTTL,
		NumKeys: numKeys,
	}
	if m.includeParams {
		entry.Params = *params
	}
	m.calls = append(m.calls, entry)
	if ttl > maxTTL {
		return "", "", fmt.Errorf("TTL of %v exceeds max TTL of %v", ttl, maxTTL)
	}
	return "acct", "token", nil
}

func (m *mockTokenCreator) Calls() []MockTokenCreatorEntry {
	c := m.calls
	m.calls = []MockTokenCreatorEntry{}
	return c
}
