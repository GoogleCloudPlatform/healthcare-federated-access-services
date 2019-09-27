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

package main

import (
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh"
)

// ClaimRepository (R)
type ClaimRepository struct {
	Claim ga4gh.Claim
}

// FetchClaim returns the requested claim.
func (r *ClaimRepository) FetchClaim(t Token) (ga4gh.Claim, error) {
	return r.Claim, nil
}
