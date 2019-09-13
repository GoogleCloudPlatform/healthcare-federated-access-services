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
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log"
	"net/http"

	"gopkg.in/square/go-jose.v2"
	"github.com/dgrijalva/jwt-go"
	"github.com/coreos/go-oidc"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/httptestclient"
	ipb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/ic/v1"
)

const (
	oidcPrefix         = "/oidc"
	oidcWellKnownPath  = "/.well-known"
	oidcConfiguarePath = oidcWellKnownPath + "/openid-configuration"
	oidcJwksPath       = oidcWellKnownPath + "/jwks"
)

// Server is a fake OIDC issuer server for testing.
type Server struct {
	issuerURL  string
	client     *http.Client
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// New returns Server
func New(issuerURL string) (*Server, error) {
	reader := rand.Reader
	const bitSize = 2048

	key, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		return nil, err
	}

	s := &Server{
		issuerURL:  issuerURL,
		privateKey: key,
		publicKey:  &key.PublicKey,
	}

	mux := http.NewServeMux()
	mux.HandleFunc(oidcPrefix+oidcConfiguarePath, s.oidcWellKnownConfig)
	mux.HandleFunc(oidcPrefix+oidcJwksPath, s.oidcKeys)
	client := httptestclient.New(mux)
	s.client = client

	return s, nil
}

// Sign the jwt with the pivate key in Server.
func (s *Server) Sign(header map[string]string, claim jwt.Claims) (string, error) {
	jot := jwt.NewWithClaims(jwt.SigningMethodRS256, claim)

	for k, v := range header {
		jot.Header[k] = v
	}

	return jot.SignedString(s.privateKey)
}

// ContextWithClient injects stub http client to context.
func (s *Server) ContextWithClient(ctx context.Context) context.Context {
	return oidc.ClientContext(ctx, s.client)
}

func (s *Server) oidcWellKnownConfig(w http.ResponseWriter, r *http.Request) {
	conf := &ipb.OidcConfig{
		Issuer:  s.issuerURL,
		JwksUri: s.issuerURL + oidcJwksPath,
	}

	if err := json.NewEncoder(w).Encode(conf); err != nil {
		log.Printf("Marshal failed: %q", err)
	}
}

func (s *Server) oidcKeys(w http.ResponseWriter, r *http.Request) {
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       s.publicKey,
				Algorithm: "RS256",
				Use:       "sig",
				KeyID:     "kid",
			},
		},
	}

	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		log.Printf("Marshal failed: %q", err)
	}
}
