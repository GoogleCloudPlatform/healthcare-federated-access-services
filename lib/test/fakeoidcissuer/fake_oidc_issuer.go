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

// Package fakeoidcissuer contains a fake OIDC issuer which can use in go-oidc provider.
package fakeoidcissuer

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"gopkg.in/square/go-jose.v2"
	"github.com/dgrijalva/jwt-go"
	"github.com/coreos/go-oidc"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/playground"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/httptestclient"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys"
	dampb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1"
	ipb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/ic/v1"
)

const (
	oidcPrefix         = "/oidc"
	oidcWellKnownPath  = "/.well-known"
	oidcConfiguarePath = oidcWellKnownPath + "/openid-configuration"
	oidcJwksPath       = oidcWellKnownPath + "/jwks"
	oidcUserInfoPath   = "/userinfo"
)

// Server is a fake OIDC issuer server for testing.
type Server struct {
	issuerURL string
	client    *http.Client
	key       *testkeys.Key
	cfg       *dampb.DamConfig
}

// New returns Server
func New(issuerURL string, key *testkeys.Key, service, path string) (*Server, error) {
	var cfg *dampb.DamConfig
	if len(service) > 0 && len(path) > 0 {
		cfg = &dampb.DamConfig{}
		store := storage.NewMemoryStorage(service, path)
		if err := store.ReadTx(storage.ConfigDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, cfg, nil); err != nil {
			return nil, err
		}
	}

	s := &Server{
		issuerURL: issuerURL,
		key:       key,
		cfg:       cfg,
	}

	mux := http.NewServeMux()
	mux.HandleFunc(oidcPrefix+oidcConfiguarePath, s.oidcWellKnownConfig)
	mux.HandleFunc(oidcPrefix+oidcJwksPath, s.oidcKeys)
	mux.HandleFunc(oidcPrefix+oidcUserInfoPath, s.oidcUserInfo)
	client := httptestclient.New(mux)
	s.client = client

	return s, nil
}

// Sign the jwt with the private key in Server.
func (s *Server) Sign(header map[string]string, claim jwt.Claims) (string, error) {
	jot := jwt.NewWithClaims(jwt.SigningMethodRS256, claim)

	for k, v := range header {
		jot.Header[k] = v
	}

	return jot.SignedString(s.key.Private)
}

// ContextWithClient injects stub http client to context.
func (s *Server) ContextWithClient(ctx context.Context) context.Context {
	return oidc.ClientContext(ctx, s.client)
}

// Config returns the DAM configuration currently in use.
func (s *Server) Config() *dampb.DamConfig {
	return s.cfg
}

func (s *Server) oidcWellKnownConfig(w http.ResponseWriter, r *http.Request) {
	conf := &ipb.OidcConfig{
		Issuer:           s.issuerURL,
		JwksUri:          s.issuerURL + oidcJwksPath,
		UserinfoEndpoint: s.issuerURL + oidcUserInfoPath,
	}

	if err := json.NewEncoder(w).Encode(conf); err != nil {
		log.Printf("Marshal failed: %q", err)
	}
}

func (s *Server) oidcKeys(w http.ResponseWriter, r *http.Request) {
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       s.key.Public,
				Algorithm: "RS256",
				Use:       "sig",
				KeyID:     s.key.ID,
			},
		},
	}

	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		log.Printf("Marshal failed: %q", err)
	}
}

func (s *Server) oidcUserInfo(w http.ResponseWriter, r *http.Request) {
	parts := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		common.HandleError(http.StatusUnauthorized, fmt.Errorf("missing or invalid Authorization header"), w)
		return
	}
	src, err := common.ConvertTokenToIdentityUnsafe(parts[1])
	if err != nil {
		common.HandleError(http.StatusUnauthorized, fmt.Errorf("invalid Authorization token"), w)
		return
	}
	sub := src.Subject
	var persona *dampb.TestPersona
	var pname string
	for pn, p := range s.cfg.TestPersonas {
		if pn == sub || (p.Passport.StandardClaims != nil && p.Passport.StandardClaims["sub"] == sub) {
			pname = pn
			persona = p
			break
		}
	}
	if persona == nil {
		common.HandleError(http.StatusUnauthorized, fmt.Errorf("persona %q not found", sub), w)
		return
	}
	id, err := playground.PersonaToIdentity(pname, persona, "openid ga4gh_passport_v1", s.issuerURL)
	if err != nil {
		common.HandleError(http.StatusUnauthorized, fmt.Errorf("preparing persona %q: %v", sub, err), w)
		return
	}
	data, err := json.Marshal(id)
	if err != nil {
		common.HandleError(http.StatusInternalServerError, fmt.Errorf("cannot encode user identity %q into JSON: %v", sub, err), w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	common.AddCorsHeaders(w)
	w.Write(data)
}
