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
	"fmt"
	"net/http"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common" /* copybara-comment: common */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/oathclients" /* copybara-comment: oathclients */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/translator" /* copybara-comment: translator */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/ic/v1" /* copybara-comment: go_proto */
)

// IdentityProviders returns part of config: Identity Providers
func (s *Service) IdentityProviders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request method not supported: %q", r.Method), w)
		return
	}
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	resp := &pb.GetIdentityProvidersResponse{
		IdentityProviders: make(map[string]*cpb.IdentityProvider),
	}
	for name, idp := range cfg.IdentityProviders {
		resp.IdentityProviders[name] = makeIdentityProvider(idp)
	}
	common.SendResponse(resp, w)
}

// PassportTranslators returns part of config: Passport Translators
func (s *Service) PassportTranslators(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request method not supported: %q", r.Method), w)
		return
	}
	out := translator.GetPassportTranslators()
	common.SendResponse(out, w)
}

// HTTP handler for ".../clients/{name}"
// Return self client information.
func (s *Service) clientFactory() *common.HandlerFactory {
	c := &clientService{s: s}

	return &common.HandlerFactory{
		TypeName:            "client",
		PathPrefix:          clientPath,
		HasNamedIdentifiers: true,
		// Only return self information, does not need admin permission.
		IsAdmin: false,
		NewHandler: func(w http.ResponseWriter, r *http.Request) common.HandlerInterface {
			return oathclients.NewClientHandler(w, r, c)
		},
	}
}
