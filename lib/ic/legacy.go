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

	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/handlerfactory" /* copybara-comment: handlerfactory */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/ic/v1" /* copybara-comment: go_proto */
)

// This file contains a number of legacy endpoints that will be removed.

var (
	placeholderOrNameRE = regexp.MustCompile(`^(-|[A-Za-z][-_A-Za-z0-9\.]{1,30}[A-Za-z0-9])$`)
	placeholderName     = "-"
	adminSubjectRE      = regexp.MustCompile(`^[\w][^/\\]*@[\w][^/\\]*$`)
)

// HTTP handler for  "/identity/v1alpha/{realm}/admin/subjects/{name}/account/claims"
func (s *Service) adminClaimsFactory() *handlerfactory.Options {
	return &handlerfactory.Options{
		TypeName:            "adminClaims",
		PathPrefix:          adminClaimsPath,
		HasNamedIdentifiers: false,
		NameChecker: map[string]*regexp.Regexp{
			"name": adminSubjectRE,
		},
		Service: func() handlerfactory.Service {
			return &adminClaims{
				s:     s,
				input: &pb.SubjectClaimsRequest{},
			}
		},
	}
}

type adminClaims struct {
	s     *Service
	item  *cpb.Account
	input *pb.SubjectClaimsRequest
	save  *cpb.Account
	cfg   *pb.IcConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func (c *adminClaims) Setup(r *http.Request, tx storage.Tx) (int, error) {
	cfg, _, id, status, err := c.s.handlerSetup(tx, r, noScope, c.input)
	c.cfg = cfg
	c.id = id
	c.tx = tx
	return status, err
}
func (c *adminClaims) LookupItem(r *http.Request, name string, vars map[string]string) bool {
	acct, _, err := c.s.scim.LookupAccount(name, getRealm(r), true, c.tx)
	if err != nil {
		return false
	}
	c.item = acct
	return true
}
func (c *adminClaims) NormalizeInput(r *http.Request, name string, vars map[string]string) error {
	if err := httputils.DecodeProtoReq(c.input, r); err != nil {
		return err
	}
	return nil
}
func (c *adminClaims) Get(r *http.Request, name string) (proto.Message, error) {
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

	return &pb.SubjectClaimsResponse{Assertions: out}, nil
}
func (c *adminClaims) Post(r *http.Request, name string) (proto.Message, error) {
	return nil, fmt.Errorf("POST not allowed")
}
func (c *adminClaims) Put(r *http.Request, name string) (proto.Message, error) {
	return nil, fmt.Errorf("PUT not allowed")
}
func (c *adminClaims) Patch(r *http.Request, name string) (proto.Message, error) {
	return nil, fmt.Errorf("PATCH not allowed")
}
func (c *adminClaims) Remove(r *http.Request, name string) (proto.Message, error) {
	if c.input.Modification != nil && c.input.Modification.DryRun {
		return nil, nil
	}
	c.save = &cpb.Account{}
	proto.Merge(c.save, c.item)
	for _, link := range c.save.ConnectedAccounts {
		link.Passport = &cpb.Passport{}
	}
	return nil, nil
}
func (c *adminClaims) CheckIntegrity(*http.Request) *status.Status {
	return nil
}
func (c *adminClaims) Save(r *http.Request, tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	if c.save == nil || (c.input.Modification != nil && c.input.Modification.DryRun) {
		return nil
	}
	if err := c.s.scim.SaveAccount(c.item, c.save, desc, r, c.id.Subject, c.tx); err != nil {
		return err
	}
	return nil
}

// HTTP handler for  "/identity/v1alpha/{realm}/admin/tokens"
func (s *Service) adminTokenMetadataFactory() *handlerfactory.Options {
	return &handlerfactory.Options{
		TypeName:            "tokens",
		PathPrefix:          adminTokenMetadataPath,
		HasNamedIdentifiers: false,
		Service: func() handlerfactory.Service {
			return &adminTokenMetadataHandler{
				s:     s,
				input: &pb.TokensMetadataRequest{},
			}
		},
	}
}

type adminTokenMetadataHandler struct {
	s     *Service
	input *pb.TokensMetadataRequest
	item  map[string]*pb.TokenMetadata
	tx    storage.Tx
}

func (h *adminTokenMetadataHandler) Setup(r *http.Request, tx storage.Tx) (int, error) {
	h.tx = tx
	_, _, _, status, err := h.s.handlerSetup(tx, r, noScope, h.input)
	return status, err
}

func (h *adminTokenMetadataHandler) LookupItem(r *http.Request, name string, vars map[string]string) bool {
	h.item = make(map[string]*pb.TokenMetadata)
	m := make(map[string]map[string]proto.Message)
	_, err := h.s.store.MultiReadTx(storage.TokensDatatype, getRealm(r), storage.DefaultUser, nil, 0, storage.MaxPageSize, m, &pb.TokenMetadata{}, h.tx)
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

func (h *adminTokenMetadataHandler) NormalizeInput(r *http.Request, name string, vars map[string]string) error {
	return httputils.DecodeProtoReq(h.input, r)
}

func (h *adminTokenMetadataHandler) Get(r *http.Request, name string) (proto.Message, error) {
	item := h.item
	if len(item) == 0 {
		item = nil
	}
	return &pb.TokensMetadataResponse{TokensMetadata: item}, nil
}

func (h *adminTokenMetadataHandler) Post(r *http.Request, name string) (proto.Message, error) {
	return nil, fmt.Errorf("POST not allowed")
}

func (h *adminTokenMetadataHandler) Put(r *http.Request, name string) (proto.Message, error) {
	return nil, fmt.Errorf("PUT not allowed")
}

func (h *adminTokenMetadataHandler) Patch(r *http.Request, name string) (proto.Message, error) {
	return nil, fmt.Errorf("PATCH not allowed")
}

func (h *adminTokenMetadataHandler) Remove(r *http.Request, name string) (proto.Message, error) {
	return nil, h.s.store.MultiDeleteTx(storage.TokensDatatype, getRealm(r), storage.DefaultUser, h.tx)
}

func (h *adminTokenMetadataHandler) CheckIntegrity(*http.Request) *status.Status {
	return nil
}

func (h *adminTokenMetadataHandler) Save(r *http.Request, tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return nil
}
