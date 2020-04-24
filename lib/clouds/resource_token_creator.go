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

// Package clouds provides interfaces for accessing cloud APIs
package clouds

import (
	"context"
	"time"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
)

// ResourceTokenCreationParams provides information on a set of items to perform an action upon.
type ResourceTokenCreationParams struct {
	AccountProject string
	Items          []map[string]string
	Roles          []string
	Scopes         []string
	TokenFormat    string
	BillingProject string
}

// ResourceTokenResult is returned from GetTokenWithTTL().
type ResourceTokenResult struct {
	Account    string
	Token      string
	AccountKey string
	Format     string
}

// ResourceTokenCreator abstracts token creation for resource accessing in cloud platforms. This refers to Service Account Warehouses (SAWs) in GCP and our communication.
type ResourceTokenCreator interface {

	// RegisterAccountProject registers account hosting project in key garbage collector.
	RegisterAccountProject(project string, tx storage.Tx) error

	// UnregisterAccountProject (eventually) removes a project from the active state, and allows cleanup work to be performed.
	UnregisterAccountProject(project string, tx storage.Tx) error

	// UpdateSettings alters resource management settings.
	UpdateSettings(maxRequestedTTL time.Duration, keysPerAccount int, tx storage.Tx) error

	// MintTokenWithTTL returns an account and a newly minted resource token for resource accessing.
	MintTokenWithTTL(ctx context.Context, id string, ttl, maxTTL time.Duration, numKeys int, params *ResourceTokenCreationParams) (*ResourceTokenResult, error)

	// GetTokenMetadata returns an access token based on its name.
	GetTokenMetadata(ctx context.Context, project, id, name string) (*cpb.TokenMetadata, error)

	// ListTokenMetadata returns a list of outstanding access tokens.
	ListTokenMetadata(ctx context.Context, project, id string) ([]*cpb.TokenMetadata, error)

	// DeleteTokens removes tokens belonging to 'id' with given names.
	// If 'names' is empty, delete all tokens belonging to 'id'.
	DeleteTokens(ctx context.Context, project, id string, names []string) error
}
