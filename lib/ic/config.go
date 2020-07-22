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

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/handlerfactory" /* copybara-comment: handlerfactory */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/oathclients" /* copybara-comment: oathclients */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/timeutil" /* copybara-comment: timeutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/translator" /* copybara-comment: translator */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/ic/v1" /* copybara-comment: go_proto */
)

// IdentityProviders returns part of config: Identity Providers
func (s *Service) IdentityProviders(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		httputils.WriteError(w, status.Errorf(codes.Unavailable, "%v", err))
		return
	}
	resp := &pb.GetIdentityProvidersResponse{
		IdentityProviders: make(map[string]*cpb.IdentityProvider),
	}
	for name, idp := range cfg.IdentityProviders {
		resp.IdentityProviders[name] = makeIdentityProvider(idp)
	}
	httputils.WriteResp(w, resp)
}

// LocaleMetadata implements the corresponding REST API endpoint.
func (s *Service) LocaleMetadata(w http.ResponseWriter, r *http.Request) {
	type response struct {
		Locales   map[string]*timeutil.LocaleInfo   `json:"locales"`
		TimeZones map[string]*timeutil.TimezoneInfo `json:"timeZones"`
	}
	httputils.WriteNonProtoResp(w, &response{Locales: timeutil.GetLocales(), TimeZones: timeutil.GetTimeZones()})
}

// PassportTranslators returns part of config: Passport Translators
func (s *Service) PassportTranslators(w http.ResponseWriter, r *http.Request) {
	out := translator.GetPassportTranslators()
	httputils.WriteResp(w, out)
}

// HTTP handler for ".../clients/{name}"
// Return self client information.
func (s *Service) clientFactory() *handlerfactory.Options {
	c := &clientService{s: s}

	return &handlerfactory.Options{
		TypeName:            "client",
		PathPrefix:          clientPath,
		HasNamedIdentifiers: true,
		Service: func() handlerfactory.Service {
			return oathclients.NewClientHandler(c)
		},
	}
}
