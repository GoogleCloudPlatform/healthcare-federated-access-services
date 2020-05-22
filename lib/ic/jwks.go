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

package ic

import (
	"encoding/json"
	"net/http"

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
)

// JWKS returns the JSON Web Key Set response for visas. Note that this is
// a different set of keys than what Hydra uses.
func (s *Service) JWKS(w http.ResponseWriter, r *http.Request) {
	keys := s.signer.PublicKeys()
	b, err := json.Marshal(keys)
	if err != nil {
		httputils.WriteError(w, status.Errorf(codes.Unavailable, "writing jwks to json: %v", err))
		return
	}
	w.Write(b)
}
