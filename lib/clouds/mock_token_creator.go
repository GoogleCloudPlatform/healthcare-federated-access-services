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

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1"
)

type MockTokenCreatorEntry struct {
	AccountID string
	TokenID   string
	TTL       time.Duration
	MaxTTL    time.Duration
	NumKeys   int
	Params    ResourceTokenCreationParams
	IssuedAt  int64
	Expires   int64
	Token     string
}

// MockTokenCreator provides a token creator implementation for testing.
type MockTokenCreator struct {
	includeParams bool
	calls         []MockTokenCreatorEntry
	tokens        map[string][]*cpb.TokenMetadata
	tokID         int64
}

// NewMockTokenCreator creates a mock ResourceTokenCreator.
func NewMockTokenCreator(includeParams bool) *MockTokenCreator {
	return &MockTokenCreator{
		includeParams: includeParams,
		calls:         []MockTokenCreatorEntry{},
		tokens:        make(map[string][]*cpb.TokenMetadata),
		tokID:         0,
	}
}

// RegisterAccountProject registers account hosting project in key garbage collector.
func (m *MockTokenCreator) RegisterAccountProject(realm, project string, maxRequestedTTL int, keysPerAccount int) error {
	return nil
}

// MintTokenWithTTL returns an account and a resource token for resource accessing.
func (m *MockTokenCreator) MintTokenWithTTL(ctx context.Context, id string, ttl, maxTTL time.Duration, numKeys int, params *ResourceTokenCreationParams) (*ResourceTokenResult, error) {
	m.tokID++
	tokenID := fmt.Sprintf("%d", m.tokID)
	entry := MockTokenCreatorEntry{
		AccountID: id,
		TokenID:   tokenID,
		TTL:       ttl,
		MaxTTL:    maxTTL,
		NumKeys:   numKeys,
		IssuedAt:  m.tokID,
		Expires:   m.tokID + 1000,
		Token:     "token_" + tokenID,
	}
	if m.includeParams {
		entry.Params = *params
	}
	tokenUser := testTokenUser(params.AccountProject, id)
	list, ok := m.tokens[tokenUser]
	if !ok {
		list = []*cpb.TokenMetadata{}
	}
	m.tokens[tokenUser] = append(list, &cpb.TokenMetadata{
		Name:     entry.TokenID,
		IssuedAt: fmt.Sprintf("%d", entry.IssuedAt),
		Expires:  fmt.Sprintf("%d", entry.Expires),
	})
	m.calls = append(m.calls, entry)
	if ttl > maxTTL {
		return nil, fmt.Errorf("TTL of %v exceeds max TTL of %v", ttl, maxTTL)
	}
	return &ResourceTokenResult{
		Account: "acct",
		Token:   entry.Token,
		Format:  "base64",
	}, nil
}

func testTokenUser(project, id string) string {
	return project + "/" + id
}

// GetTokenMetadata returns an access token based on its name.
func (m *MockTokenCreator) GetTokenMetadata(ctx context.Context, project, id, name string) (*cpb.TokenMetadata, error) {
	list, err := m.ListTokenMetadata(ctx, project, id)
	if err != nil {
		return nil, fmt.Errorf("getting token: %v", err)
	}
	for _, meta := range list {
		if meta.Name == name {
			return meta, nil
		}
	}
	return nil, fmt.Errorf("token %q not found", name)
}

// ListTokenMetadata returns a list of outstanding access tokens.
func (m *MockTokenCreator) ListTokenMetadata(ctx context.Context, project, id string) ([]*cpb.TokenMetadata, error) {
	tokenUser := testTokenUser(project, id)
	list, ok := m.tokens[tokenUser]
	if !ok {
		return []*cpb.TokenMetadata{}, nil
	}
	return list, nil
}

// DeleteTokens removes tokens belonging to 'id' with given names.
// If 'names' is empty, delete all tokens belonging to 'id'.
func (m *MockTokenCreator) DeleteTokens(ctx context.Context, project, id string, names []string) error {
	tokenUser := testTokenUser(project, id)
	if len(names) == 0 {
		delete(m.tokens, tokenUser)
		return nil
	}
	list, ok := m.tokens[tokenUser]
	if !ok {
		return fmt.Errorf("namespace %q empty (cannot delete %d entries)", tokenUser, len(names))
	}
	for _, name := range names {
		found := false
		for i, entry := range list {
			if entry.Name == name {
				if len(list) == 1 {
					list = []*cpb.TokenMetadata{}
					delete(m.tokens, tokenUser)
				} else {
					list = append(list[:i-1], list[i+1:]...)
				}
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("namespace %q token %q not found", tokenUser, name)
		}
	}
	return nil
}

func (m *MockTokenCreator) Calls() []MockTokenCreatorEntry {
	c := m.calls
	m.calls = []MockTokenCreatorEntry{}
	return c
}
