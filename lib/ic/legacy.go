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
	"regexp"

	"github.com/golang/protobuf/proto" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/handlerfactory" /* copybara-comment: handlerfactory */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/ic/v1" /* copybara-comment: go_proto */
)

// This file contains a number of legacy endpoints that will be removed.

var (
	placeholderOrNameRE = regexp.MustCompile(`^(-|[A-Za-z][-_A-Za-z0-9\.]{1,30}[A-Za-z0-9])$`)
	placeholderName     = "-"
)

// HTTP handler for  "/identity/v1alpha/{realm}/admin/subjects/{name}/account/claims"
func (s *Service) adminClaimsFactory() *handlerfactory.HandlerFactory {
	return &handlerfactory.HandlerFactory{
		TypeName:            "adminClaims",
		PathPrefix:          adminClaimsPath,
		HasNamedIdentifiers: false,
		NameChecker: map[string]*regexp.Regexp{
			"name": regexp.MustCompile(`^[\w][^/\\]*@[\w][^/\\]*$`),
		},
		NewHandler: func(w http.ResponseWriter, r *http.Request) handlerfactory.HandlerInterface {
			return &adminClaims{
				s:     s,
				w:     w,
				r:     r,
				input: &pb.SubjectClaimsRequest{},
			}
		},
	}
}

type adminClaims struct {
	s     *Service
	w     http.ResponseWriter
	r     *http.Request
	item  *cpb.Account
	input *pb.SubjectClaimsRequest
	save  *cpb.Account
	cfg   *pb.IcConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func (c *adminClaims) Setup(tx storage.Tx) (int, error) {
	cfg, _, id, status, err := c.s.handlerSetup(tx, c.r, noScope, c.input)
	c.cfg = cfg
	c.id = id
	c.tx = tx
	return status, err
}
func (c *adminClaims) LookupItem(name string, vars map[string]string) bool {
	acct, _, err := c.s.scim.LookupAccount(name, getRealm(c.r), true, c.tx)
	if err != nil {
		return false
	}
	c.item = acct
	return true
}
func (c *adminClaims) NormalizeInput(name string, vars map[string]string) error {
	if err := httputil.DecodeProtoReq(c.input, c.r); err != nil {
		return err
	}
	return nil
}
func (c *adminClaims) Get(name string) error {
	// Collect all claims across linked accounts.
	out := []*cpb.Assertion{}
	for _, link := range c.item.ConnectedAccounts {
		if link.Passport == nil {
			continue
		}
		for _, v := range link.Passport.Ga4GhAssertions {
			out = append(out, v)
		}
	}

	httputil.WriteProtoResp(c.w, &pb.SubjectClaimsResponse{Assertions: out})
	return nil
}
func (c *adminClaims) Post(name string) error {
	return fmt.Errorf("POST not allowed")
}
func (c *adminClaims) Put(name string) error {
	return fmt.Errorf("PUT not allowed")
}
func (c *adminClaims) Patch(name string) error {
	return fmt.Errorf("PATCH not allowed")
}
func (c *adminClaims) Remove(name string) error {
	if c.input.Modification != nil && c.input.Modification.DryRun {
		return nil
	}
	c.save = &cpb.Account{}
	proto.Merge(c.save, c.item)
	for _, link := range c.save.ConnectedAccounts {
		link.Passport = &cpb.Passport{}
	}
	return nil
}
func (c *adminClaims) CheckIntegrity() *status.Status {
	return nil
}
func (c *adminClaims) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	if c.save == nil || (c.input.Modification != nil && c.input.Modification.DryRun) {
		return nil
	}
	if err := c.s.scim.SaveAccount(c.item, c.save, desc, c.r, c.id.Subject, c.tx); err != nil {
		return err
	}
	return nil
}

// HTTP handler for  "/identity/v1alpha/{realm}/admin/tokens"
func (s *Service) adminTokenMetadataFactory() *handlerfactory.HandlerFactory {
	return &handlerfactory.HandlerFactory{
		TypeName:            "tokens",
		PathPrefix:          adminTokenMetadataPath,
		HasNamedIdentifiers: false,
		NewHandler: func(w http.ResponseWriter, r *http.Request) handlerfactory.HandlerInterface {
			return &adminTokenMetadataHandler{
				s:     s,
				w:     w,
				r:     r,
				input: &pb.TokensMetadataRequest{},
			}
		},
	}
}

type adminTokenMetadataHandler struct {
	s     *Service
	w     http.ResponseWriter
	r     *http.Request
	input *pb.TokensMetadataRequest
	item  map[string]*pb.TokenMetadata
	tx    storage.Tx
}

func (h *adminTokenMetadataHandler) Setup(tx storage.Tx) (int, error) {
	h.tx = tx
	_, _, _, status, err := h.s.handlerSetup(tx, h.r, noScope, h.input)
	return status, err
}

func (h *adminTokenMetadataHandler) LookupItem(name string, vars map[string]string) bool {
	h.item = make(map[string]*pb.TokenMetadata)
	m := make(map[string]map[string]proto.Message)
	_, err := h.s.store.MultiReadTx(storage.TokensDatatype, getRealm(h.r), storage.DefaultUser, nil, 0, storage.MaxPageSize, m, &pb.TokenMetadata{}, h.tx)
	if err != nil {
		return false
	}
	for userKey, userVal := range m {
		for idKey, idVal := range userVal {
			if id, ok := idVal.(*pb.TokenMetadata); ok {
				h.item[userKey+"/"+idKey] = id
			}
		}
	}
	return true
}

func (h *adminTokenMetadataHandler) NormalizeInput(name string, vars map[string]string) error {
	return httputil.DecodeProtoReq(h.input, h.r)
}

func (h *adminTokenMetadataHandler) Get(name string) error {
	item := h.item
	if len(item) == 0 {
		item = nil
	}
	httputil.WriteProtoResp(h.w, &pb.TokensMetadataResponse{TokensMetadata: item})
	return nil
}

func (h *adminTokenMetadataHandler) Post(name string) error {
	return fmt.Errorf("POST not allowed")
}

func (h *adminTokenMetadataHandler) Put(name string) error {
	return fmt.Errorf("PUT not allowed")
}

func (h *adminTokenMetadataHandler) Patch(name string) error {
	return fmt.Errorf("PATCH not allowed")
}

func (h *adminTokenMetadataHandler) Remove(name string) error {
	return h.s.store.MultiDeleteTx(storage.TokensDatatype, getRealm(h.r), storage.DefaultUser, h.tx)
}

func (h *adminTokenMetadataHandler) CheckIntegrity() *status.Status {
	return nil
}

func (h *adminTokenMetadataHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return nil
}
