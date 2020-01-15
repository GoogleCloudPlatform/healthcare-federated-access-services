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
	"net/http"

	"github.com/dgrijalva/jwt-go" /* copybara-comment */
	"github.com/coreos/go-oidc" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/persona" /* copybara-comment: persona */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/httptestclient" /* copybara-comment: httptestclient */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */
	dampb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
)

// Server is a fake OIDC issuer server for testing.
type Server struct {
	broker *persona.Server
	client *http.Client
}

// New returns Server
func New(issuerURL string, key *testkeys.Key, service, path string, useOIDCPrefix bool) (*Server, error) {
	broker, err := persona.NewBroker(issuerURL, key, service, path, useOIDCPrefix)
	if err != nil {
		return nil, err
	}
	s := &Server{
		broker: broker,
		client: httptestclient.New(broker.Handler),
	}
	return s, nil
}

// Sign the jwt with the private key in Server.
func (s *Server) Sign(header map[string]string, claim jwt.Claims) (string, error) {
	return s.broker.Sign(header, claim)
}

// ContextWithClient injects stub http client to context.
func (s *Server) ContextWithClient(ctx context.Context) context.Context {
	return oidc.ClientContext(ctx, s.client)
}

// Config returns the DAM configuration currently in use.
func (s *Server) Config() *dampb.DamConfig {
	return s.broker.Config()
}
