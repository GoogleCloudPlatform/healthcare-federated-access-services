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
	"net/http"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/ic/v1" /* copybara-comment: go_proto */
)

// Status returns information about the job and its services.
// HTTP Handler for "/"
func (s *Service) Status(w http.ResponseWriter, r *http.Request) {
	out := &pb.GetInfoResponse{
		Name:      "Identity Concentrator",
		Versions:  []string{"v1alpha"},
		StartTime: s.startTime,
	}

	realm := httputil.GetParamOrDefault(r, "realm", storage.DefaultRealm)
	if cfg, err := s.loadConfig(nil, realm); err == nil {
		out.Ui = cfg.Ui
	}
	httputil.SendResponse(out, w)
}
