// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package translator provides implementations of the ga4gh.Translator interface for
// translating between different identity providers and GA4GH identities.
package translator

import (
	"context"

	ga4gh "github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh"
)

// Static is a ga4gh.Translator that returns a single static Identity.
type Static struct {
	Identity *ga4gh.Identity
}

// TranslateToken implements the ga4gh.Translator interface.
func (s *Static) TranslateToken(context.Context, string) (*ga4gh.Identity, error) {
	return s.Identity, nil
}
