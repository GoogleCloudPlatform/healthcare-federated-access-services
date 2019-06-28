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

	compb "google3/third_party/hcls_federated_access/common/models/go_proto"
)

// ResourceTokenCreationParams provides information on a set of items to perform an action upon.
type ResourceTokenCreationParams struct {
	AccountProject string
	Items          []map[string]string
	Roles          []string
	Scopes         []string
}

// ResourceTokenCreator abstracts token creation for resource accessing in cloud platforms. This refers to Service Account Warehouses (SAWs) in GCP and our communication.
type ResourceTokenCreator interface {

	// RegisterAccountProject registers account hosting project in key garbage collector.
	RegisterAccountProject(realm, project string, maxRequestedTTL int, keysPerAccount int) error

	// GetTokenWithTTL returns an account and a resource token for resource accessing.
	GetTokenWithTTL(ctx context.Context, id string, ttl, maxTTL time.Duration, numKeys int, params *ResourceTokenCreationParams) (string, string, error)

	// ListTokens returns a list of outstanding access tokens.
	ListTokens(ctx context.Context, project, id string) ([]*compb.TokenMetadata, error)

	// DeleteTokens removes tokens belonging to 'id' with given names.
	// If 'names' is empty, delete all tokens belonging to 'id'.
	DeleteTokens(ctx context.Context, project, id string, names []string) error
}
