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

	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/adapter" /* copybara-comment: adapter */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
)

type tokensHandler struct {
	s     *Service
	w     http.ResponseWriter
	r     *http.Request
	input *pb.TokensRequest
	item  []*cpb.TokenMetadata
	cfg   *pb.DamConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func NewTokensHandler(s *Service, w http.ResponseWriter, r *http.Request) *tokensHandler {
	return &tokensHandler{
		s:     s,
		w:     w,
		r:     r,
		input: &pb.TokensRequest{},
	}
}
func (h *tokensHandler) Setup(tx storage.Tx) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, h.r, noScope, h.input)
	h.tx = tx
	h.cfg = cfg
	h.id = id
	return status, err
}
func (h *tokensHandler) LookupItem(name string, vars map[string]string) bool {
	items, err := h.s.warehouse.ListTokenMetadata(context.Background(), h.cfg.Options.GcpServiceAccountProject, ga4gh.TokenUserID(h.id, adapter.SawMaxUserIDLength))
	if err != nil {
		return false
	}
	h.item = items
	return true
}
func (h *tokensHandler) NormalizeInput(name string, vars map[string]string) error {
	return httputil.DecodeProtoReq(h.input, h.r)
}
func (h *tokensHandler) Get(name string) error {
	item := h.item
	if len(item) == 0 {
		item = nil
	}
	if h.item != nil {
		httputil.WriteProtoResp(h.w, &pb.TokensResponse{Tokens: item})
	}
	return nil
}
func (h *tokensHandler) Post(name string) error {
	return fmt.Errorf("POST not allowed")
}
func (h *tokensHandler) Put(name string) error {
	return fmt.Errorf("PUT not allowed")
}
func (h *tokensHandler) Patch(name string) error {
	return fmt.Errorf("PATCH not allowed")
}
func (h *tokensHandler) Remove(name string) error {
	if len(h.item) == 0 {
		return nil
	}
	return h.s.warehouse.DeleteTokens(context.Background(), h.cfg.Options.GcpServiceAccountProject, ga4gh.TokenUserID(h.id, adapter.SawMaxUserIDLength), nil)
}
func (h *tokensHandler) CheckIntegrity() *status.Status {
	return nil
}
func (h *tokensHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return nil
}

/////////////////////////////////////////////////////////

type tokenHandler struct {
	s     *Service
	w     http.ResponseWriter
	r     *http.Request
	input *pb.TokenRequest
	item  *cpb.TokenMetadata
	cfg   *pb.DamConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

// NewTokenHandler is the handler for the tokens/{name} endpoint.
func NewTokenHandler(s *Service, w http.ResponseWriter, r *http.Request) *tokenHandler {
	return &tokenHandler{
		s:     s,
		w:     w,
		r:     r,
		input: &pb.TokenRequest{},
	}
}
func (h *tokenHandler) Setup(tx storage.Tx) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, h.r, noScope, h.input)
	h.tx = tx
	h.cfg = cfg
	h.id = id
	return status, err
}
func (h *tokenHandler) LookupItem(name string, vars map[string]string) bool {
	item, err := h.s.warehouse.GetTokenMetadata(context.Background(), h.cfg.Options.GcpServiceAccountProject, ga4gh.TokenUserID(h.id, adapter.SawMaxUserIDLength), name)
	if err != nil {
		return false
	}
	h.item = item
	return true
}
func (h *tokenHandler) NormalizeInput(name string, vars map[string]string) error {
	return httputil.DecodeProtoReq(h.input, h.r)
}
func (h *tokenHandler) Get(name string) error {
	httputil.WriteProtoResp(h.w, &pb.TokenResponse{Token: h.item})
	return nil
}
func (h *tokenHandler) Post(name string) error {
	return fmt.Errorf("POST not allowed")
}
func (h *tokenHandler) Put(name string) error {
	return fmt.Errorf("PUT not allowed")
}
func (h *tokenHandler) Patch(name string) error {
	return fmt.Errorf("PATCH not allowed")
}
func (h *tokenHandler) Remove(name string) error {
	list := []string{name}
	return h.s.warehouse.DeleteTokens(context.Background(), h.cfg.Options.GcpServiceAccountProject, ga4gh.TokenUserID(h.id, adapter.SawMaxUserIDLength), list)
}
func (h *tokenHandler) CheckIntegrity() *status.Status {
	return nil
}
func (h *tokenHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return nil
}
