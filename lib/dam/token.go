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

package dam

import (
	"context"
	"fmt"
	"net/http"

	"github.com/golang/protobuf/proto" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/adapter" /* copybara-comment: adapter */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
)

// TokensHandler is hanlder for tokens.
type TokensHandler struct {
	s     *Service
	input *pb.TokensRequest
	item  []*cpb.TokenMetadata
	cfg   *pb.DamConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

// NewTokensHandler creates a new TokensHandler.
func NewTokensHandler(s *Service) *TokensHandler {
	return &TokensHandler{
		s:     s,
		input: &pb.TokensRequest{},
	}
}

// Setup setups.
func (h *TokensHandler) Setup(r *http.Request, tx storage.Tx) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, r, noScope, h.input)
	h.tx = tx
	h.cfg = cfg
	h.id = id
	return status, err
}

// LookupItem looks up item.
func (h *TokensHandler) LookupItem(r *http.Request, name string, vars map[string]string) bool {
	items, err := h.s.warehouse.ListTokenMetadata(context.Background(), h.cfg.Options.GcpServiceAccountProject, ga4gh.TokenUserID(h.id, adapter.SawMaxUserIDLength))
	if err != nil {
		return false
	}
	h.item = items
	return true
}

// NormalizeInput normalizes.
func (h *TokensHandler) NormalizeInput(r *http.Request, name string, vars map[string]string) error {
	return httputil.DecodeProtoReq(h.input, r)
}

// Get gets.
func (h *TokensHandler) Get(r *http.Request, name string) (proto.Message, error) {
	item := h.item
	if len(item) == 0 {
		item = nil
	}
	if h.item != nil {
		return &pb.TokensResponse{Tokens: item}, nil
	}
	return nil, nil
}

// Post posts.
func (h *TokensHandler) Post(r *http.Request, name string) (proto.Message, error) {
	return nil, fmt.Errorf("POST not allowed")
}

// Put puts.
func (h *TokensHandler) Put(r *http.Request, name string) (proto.Message, error) {
	return nil, fmt.Errorf("PUT not allowed")
}

// Patch patches.
func (h *TokensHandler) Patch(r *http.Request, name string) (proto.Message, error) {
	return nil, fmt.Errorf("PATCH not allowed")
}

// Remove removes.
func (h *TokensHandler) Remove(r *http.Request, name string) (proto.Message, error) {
	if len(h.item) == 0 {
		return nil, nil
	}
	return nil, h.s.warehouse.DeleteTokens(context.Background(), h.cfg.Options.GcpServiceAccountProject, ga4gh.TokenUserID(h.id, adapter.SawMaxUserIDLength), nil)
}

// CheckIntegrity checks integrity.
func (h *TokensHandler) CheckIntegrity(*http.Request) *status.Status {
	return nil
}

// Save saves.
func (h *TokensHandler) Save(r *http.Request, tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return nil
}

/////////////////////////////////////////////////////////

// TokenHandler is handler for token.
type TokenHandler struct {
	s     *Service
	r     *http.Request
	input *pb.TokenRequest
	item  *cpb.TokenMetadata
	cfg   *pb.DamConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

// NewTokenHandler is the handler for the tokens/{name} endpoint.
func NewTokenHandler(s *Service) *TokenHandler {
	return &TokenHandler{
		s:     s,
		input: &pb.TokenRequest{},
	}
}

// Setup setups.
func (h *TokenHandler) Setup(r *http.Request, tx storage.Tx) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, r, noScope, h.input)
	h.tx = tx
	h.cfg = cfg
	h.id = id
	return status, err
}

// LookupItem looks up item.
func (h *TokenHandler) LookupItem(r *http.Request, name string, vars map[string]string) bool {
	item, err := h.s.warehouse.GetTokenMetadata(context.Background(), h.cfg.Options.GcpServiceAccountProject, ga4gh.TokenUserID(h.id, adapter.SawMaxUserIDLength), name)
	if err != nil {
		return false
	}
	h.item = item
	return true
}

// NormalizeInput normalizes.
func (h *TokenHandler) NormalizeInput(r *http.Request, name string, vars map[string]string) error {
	return httputil.DecodeProtoReq(h.input, r)
}

// Get gets.
func (h *TokenHandler) Get(r *http.Request, name string) (proto.Message, error) {
	return &pb.TokenResponse{Token: h.item}, nil
}

// Post posts.
func (h *TokenHandler) Post(r *http.Request, name string) (proto.Message, error) {
	return nil, fmt.Errorf("POST not allowed")
}

// Put puts.
func (h *TokenHandler) Put(r *http.Request, name string) (proto.Message, error) {
	return nil, fmt.Errorf("PUT not allowed")
}

// Patch patches.
func (h *TokenHandler) Patch(r *http.Request, name string) (proto.Message, error) {
	return nil, fmt.Errorf("PATCH not allowed")
}

// Remove removes.
func (h *TokenHandler) Remove(r *http.Request, name string) (proto.Message, error) {
	list := []string{name}
	return nil, h.s.warehouse.DeleteTokens(context.Background(), h.cfg.Options.GcpServiceAccountProject, ga4gh.TokenUserID(h.id, adapter.SawMaxUserIDLength), list)
}

// CheckIntegrity checks integrity.
func (h *TokenHandler) CheckIntegrity(*http.Request) *status.Status {
	return nil
}

// Save saves.
func (h *TokenHandler) Save(r *http.Request, tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return nil
}
