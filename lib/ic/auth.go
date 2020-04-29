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

// TODO move to icauth package.

package ic

import (
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/hydra" /* copybara-comment: hydra */
)

// authChecker provides helpers for auth.Checker.
type authChecker struct {
	s *Service
}

func (s *authChecker) fetchClientSecrets() (map[string]string, error) {
	sec, err := s.s.loadSecrets(nil)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "loadSecrets failed: %v", err)
	}

	return sec.ClientSecrets, nil
}

// transformIdentity move "identities" claim in "ext" claim to top level identities claim for hydra.
func (s *authChecker) transformIdentity(id *ga4gh.Identity) *ga4gh.Identity {
	if !s.s.useHydra {
		return id
	}

	return hydra.NormalizeIdentity(id)
}
