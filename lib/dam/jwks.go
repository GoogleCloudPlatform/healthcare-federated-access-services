// Copyright 2020 Google LLC.
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

package dam

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"gopkg.in/square/go-jose.v2" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */

	glog "github.com/golang/glog" /* copybara-comment */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
)

func (s *Service) gatekeeperTokenIssuerURL() string {
	return strings.TrimRight(s.domainURL, "/") + gatekeeperIssuer
}

/////////////////////////////////////////////////////////
// OIDC related

// OidcWellKnownConfig handle OpenID Provider configuration request.
func (s *Service) OidcWellKnownConfig(w http.ResponseWriter, r *http.Request) {
	conf := &pb.OidcConfig{
		Issuer:  s.gatekeeperTokenIssuerURL(),
		JwksUri: strings.TrimRight(s.domainURL, "/") + oidcJwksPath,
	}

	httputils.WriteResp(w, conf)
}

// OidcKeys handle OpenID Provider jwks request.
func (s *Service) OidcKeys(w http.ResponseWriter, r *http.Request) {
	secrets, err := s.loadSecrets(nil)
	if err != nil {
		httputils.WriteError(w, status.Errorf(codes.Unavailable, "OidcKeys loadSecrets failed: %v", err))
		return
	}

	if len(secrets.GatekeeperTokenKeys.PublicKey) == 0 {
		httputils.WriteError(w, status.Errorf(codes.Internal, "OidcKeys gatekeeper token not found"))
		return
	}

	block, _ := pem.Decode([]byte(secrets.GatekeeperTokenKeys.PublicKey))
	pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		httputils.WriteError(w, status.Errorf(codes.Internal, "parsing public key for gatekeeper token: %v", err))
		return
	}

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       pub,
				Algorithm: "RS256",
				Use:       "sig",
				KeyID:     "kid",
			},
		},
	}

	data, err := json.Marshal(jwks)
	if err != nil {
		glog.Infof("Marshal failed: %v", err)
		httputils.WriteError(w, status.Errorf(codes.Internal, "OidcKeys Marshal failed: %v", err))
		return
	}

	w.Write(data)
}
