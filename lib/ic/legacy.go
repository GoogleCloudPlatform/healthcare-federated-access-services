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
	"strings"

	"github.com/golang/protobuf/proto" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common" /* copybara-comment: common */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/ic/v1" /* copybara-comment: go_proto */
)

// This file contains a number of legacy endpoints that will be removed.

// HTTP handler for "/identity/v1alpha/{realm}/accounts/{name}"
func (s *Service) accountFactory() *common.HandlerFactory {
	return &common.HandlerFactory{
		TypeName:            "account",
		PathPrefix:          accountPath,
		HasNamedIdentifiers: true,
		NameChecker: map[string]*regexp.Regexp{
			"name": common.PlaceholderOrNameRE,
		},
		NewHandler: func(w http.ResponseWriter, r *http.Request) common.HandlerInterface {
			return &account{
				s:     s,
				w:     w,
				r:     r,
				input: &pb.AccountRequest{},
			}
		},
	}
}

type account struct {
	s     *Service
	w     http.ResponseWriter
	r     *http.Request
	item  *cpb.Account
	input *pb.AccountRequest
	save  *cpb.Account
	cfg   *pb.IcConfig
	sec   *pb.IcSecrets
	id    *ga4gh.Identity
	tx    storage.Tx
}

func (c *account) Setup(tx storage.Tx) (int, error) {
	cfg, sec, id, status, err := c.s.handlerSetup(tx, c.r, noScope, c.input)
	c.cfg = cfg
	c.sec = sec
	c.id = id
	c.tx = tx
	return status, err
}
func (c *account) LookupItem(name string, vars map[string]string) bool {
	if name == common.PlaceholderName {
		name = c.id.Subject
	} else if strings.Contains(name, "@") {
		lookup, err := c.s.accountLookup(getRealm(c.r), name, c.tx)
		if err != nil || !isLookupActive(lookup) {
			return false
		}
		name = lookup.Subject
	}
	if _, err := c.s.permissions.CheckSubjectOrAdmin(c.id, name); err != nil {
		return false
	}
	acct, _, err := c.s.loadAccount(name, getRealm(c.r), c.tx)
	if err != nil {
		return false
	}
	c.item = acct
	return true
}
func (c *account) NormalizeInput(name string, vars map[string]string) error {
	if err := common.GetRequest(c.input, c.r); err != nil {
		return err
	}
	if c.input.Item == nil {
		c.input.Item = &cpb.Account{}
	}
	if c.input.Modification == nil {
		c.input.Modification = &pb.ConfigModification{}
	}
	if c.input.Item.Profile == nil {
		c.input.Item.Profile = &cpb.AccountProfile{}
	}
	if c.input.Item.Ui == nil {
		c.input.Item.Ui = make(map[string]string)
	}
	if c.input.Item.ConnectedAccounts == nil {
		c.input.Item.ConnectedAccounts = []*cpb.ConnectedAccount{}
	}
	for _, a := range c.input.Item.ConnectedAccounts {
		if a.Profile == nil {
			a.Profile = &cpb.AccountProfile{}
		}
		if a.Properties == nil {
			a.Properties = &cpb.AccountProperties{}
		}
		if a.Passport == nil {
			a.Passport = &cpb.Passport{}
		}
		a.ComputedIdentityProvider = nil
	}
	return nil
}
func (c *account) Get(name string) error {
	secrets, err := c.s.loadSecrets(c.tx)
	if err != nil {
		// Do not expose internal errors related to secrets to users, return generic error instead.
		return fmt.Errorf("internal system information unavailable")
	}
	common.SendResponse(&pb.AccountResponse{
		Account: c.s.makeAccount(c.r.Context(), c.item, c.cfg, secrets),
	}, c.w)
	return nil
}
func (c *account) Post(name string) error {
	return fmt.Errorf("POST not allowed")
}
func (c *account) Put(name string) error {
	return fmt.Errorf("PUT not allowed")
}
func (c *account) Patch(name string) error {
	c.save = &cpb.Account{}
	proto.Merge(c.save, c.item)
	link := common.GetParam(c.r, "link_token")
	if len(link) > 0 {
		if !hasScopes("link", c.id.Scope, matchFullScope) {
			return fmt.Errorf("bearer token unauthorized for scope %q", "link")
		}
		linkID, _, err := c.s.tokenToIdentity(link, c.r, "link:"+c.item.Properties.Subject, getRealm(c.r), c.cfg, c.sec, c.tx)
		if err != nil {
			return err
		}
		linkSub := linkID.Subject
		idSub := c.item.Properties.Subject
		if linkSub == idSub {
			return fmt.Errorf("the accounts provided are already linked together")
		}
		linkAcct, _, err := c.s.loadAccount(linkSub, getRealm(c.r), c.tx)
		if err != nil {
			return err
		}
		if linkAcct.State != storage.StateActive {
			return fmt.Errorf("the link account is not found or no longer available")
		}
		for _, acct := range linkAcct.ConnectedAccounts {
			if acct.Properties == nil || len(acct.Properties.Subject) == 0 {
				continue
			}
			if c.input.Modification != nil && c.input.Modification.DryRun {
				continue
			}
			lookup := &cpb.AccountLookup{
				Subject:  c.item.Properties.Subject,
				Revision: acct.LinkRevision,
				State:    storage.StateActive,
			}
			if err := c.s.saveAccountLookup(lookup, getRealm(c.r), acct.Properties.Subject, c.r, c.id, c.tx); err != nil {
				return fmt.Errorf("service dependencies not available; try again later")
			}
			acct.LinkRevision++
			c.save.ConnectedAccounts = append(c.save.ConnectedAccounts, acct)
		}
		linkAcct.ConnectedAccounts = make([]*cpb.ConnectedAccount, 0)
		linkAcct.State = "LINKED"
		linkAcct.Owner = c.item.Properties.Subject
		if c.input.Modification == nil || !c.input.Modification.DryRun {
			err := c.s.saveAccount(nil, linkAcct, "LINK account", c.r, c.id.Subject, c.tx)
			if err != nil {
				return err
			}
		}
	} else {
		// PATCH Profile, but not core elements like subject and timestamps.
		if len(c.input.Item.Ui) > 0 {
			c.save.Ui = c.input.Item.Ui
		}
		proto.Merge(c.save.Profile, c.input.Item.Profile)
	}
	return nil
}
func (c *account) Remove(name string) error {
	if c.input.Modification != nil && c.input.Modification.DryRun {
		return nil
	}
	c.save = &cpb.Account{}
	proto.Merge(c.save, c.item)
	for _, link := range c.save.ConnectedAccounts {
		if link.Properties == nil || len(link.Properties.Subject) == 0 {
			continue
		}
		if err := c.s.removeAccountLookup(link.LinkRevision, getRealm(c.r), link.Properties.Subject, c.r, c.id, c.tx); err != nil {
			return fmt.Errorf("service dependencies not available; try again later")
		}
	}
	c.save.ConnectedAccounts = []*cpb.ConnectedAccount{}
	c.save.State = "DELETED"
	return nil
}
func (c *account) CheckIntegrity() *status.Status {
	// TODO: add more checks for accounts here.
	return nil
}
func (c *account) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	if c.save == nil || (c.input.Modification != nil && c.input.Modification.DryRun) {
		return nil
	}
	if err := c.s.saveAccount(c.item, c.save, desc, c.r, c.id.Subject, c.tx); err != nil {
		return err
	}
	return nil
}

// HTTP handler for "/identity/v1alpha/{realm}/accounts/{name}/subjects/{subject}"
func (s *Service) accountSubjectFactory() *common.HandlerFactory {
	return &common.HandlerFactory{
		TypeName:            "accountLink",
		PathPrefix:          accountSubjectPath,
		HasNamedIdentifiers: true,
		NameChecker: map[string]*regexp.Regexp{
			// Some upstream IdPs may use a wider selection of characters, including email-looking format.
			"subject": regexp.MustCompile(`^[\w][^/\\@]*@?[\w][^/\\@]*$`),
		},
		NewHandler: func(w http.ResponseWriter, r *http.Request) common.HandlerInterface {
			return &accountLink{
				s:     s,
				w:     w,
				r:     r,
				input: &pb.AccountSubjectRequest{},
			}
		},
	}
}

type accountLink struct {
	s         *Service
	w         http.ResponseWriter
	r         *http.Request
	acct      *cpb.Account
	item      *cpb.ConnectedAccount
	itemIndex int
	input     *pb.AccountSubjectRequest
	save      *cpb.Account
	cfg       *pb.IcConfig
	id        *ga4gh.Identity
	tx        storage.Tx
}

func (c *accountLink) Setup(tx storage.Tx) (int, error) {
	cfg, _, id, status, err := c.s.handlerSetup(tx, c.r, noScope, c.input)
	c.cfg = cfg
	c.id = id
	c.tx = tx
	return status, err
}
func (c *accountLink) LookupItem(name string, vars map[string]string) bool {
	acct, _, err := c.s.loadAccount(name, getRealm(c.r), c.tx)
	if err != nil {
		return false
	}
	c.acct = acct
	if link, i := findLinkedAccount(acct, vars["subject"]); link != nil {
		c.item = link
		c.itemIndex = i
		return true
	}
	return false
}
func (c *accountLink) NormalizeInput(name string, vars map[string]string) error {
	if err := common.GetRequest(c.input, c.r); err != nil {
		return err
	}
	if c.input.Item == nil {
		c.input.Item = &cpb.ConnectedAccount{}
	}
	if c.input.Item.Profile == nil {
		c.input.Item.Profile = &cpb.AccountProfile{}
	}
	if c.input.Item.Passport == nil {
		c.input.Item.Passport = &cpb.Passport{}
	}
	c.input.Item.ComputedIdentityProvider = nil
	return nil
}
func (c *accountLink) Get(name string) error {
	secrets, err := c.s.loadSecrets(c.tx)
	if err != nil {
		// Do not expose internal errors related to secrets to users, return generic error instead.
		return fmt.Errorf("internal system information unavailable")
	}
	common.SendResponse(&pb.AccountSubjectResponse{
		Item: c.s.makeConnectedAccount(c.r.Context(), c.item, c.cfg, secrets),
	}, c.w)
	return nil
}
func (c *accountLink) Post(name string) error {
	return fmt.Errorf("POST not allowed")
}
func (c *accountLink) Put(name string) error {
	return fmt.Errorf("PUT not allowed")
}
func (c *accountLink) Patch(name string) error {
	return fmt.Errorf("PATCH not allowed")
}
func (c *accountLink) Remove(name string) error {
	if c.input.Modification != nil && c.input.Modification.DryRun {
		return nil
	}
	c.save = &cpb.Account{}
	proto.Merge(c.save, c.acct)
	c.save.ConnectedAccounts = append(c.save.ConnectedAccounts[:c.itemIndex], c.save.ConnectedAccounts[c.itemIndex+1:]...)
	if len(c.save.ConnectedAccounts) == 0 {
		return fmt.Errorf("cannot remove primary linked account; delete full account instead")
	}
	if err := c.s.removeAccountLookup(c.item.LinkRevision, getRealm(c.r), c.item.Properties.Subject, c.r, c.id, c.tx); err != nil {
		return fmt.Errorf("service dependencies not available; try again later")
	}
	return nil
}
func (c *accountLink) CheckIntegrity() *status.Status {
	// TODO: add more checks for accounts here (such as removing the primary email account).
	return nil
}
func (c *accountLink) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	if c.save == nil || (c.input.Modification != nil && c.input.Modification.DryRun) {
		return nil
	}
	if err := c.s.saveAccount(c.acct, c.save, desc, c.r, c.id.Subject, c.tx); err != nil {
		return err
	}
	return nil
}

// HTTP handler for  "/identity/v1alpha/{realm}/admin/subjects/{name}/account/claims"
func (s *Service) adminClaimsFactory() *common.HandlerFactory {
	return &common.HandlerFactory{
		TypeName:            "adminClaims",
		PathPrefix:          adminClaimsPath,
		HasNamedIdentifiers: false,
		NameChecker: map[string]*regexp.Regexp{
			"name": regexp.MustCompile(`^[\w][^/\\]*@[\w][^/\\]*$`),
		},
		NewHandler: func(w http.ResponseWriter, r *http.Request) common.HandlerInterface {
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
	acct, _, err := c.s.lookupAccount(name, getRealm(c.r), c.tx)
	if err != nil {
		return false
	}
	c.item = acct
	return true
}
func (c *adminClaims) NormalizeInput(name string, vars map[string]string) error {
	if err := common.GetRequest(c.input, c.r); err != nil {
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

	common.SendResponse(&pb.SubjectClaimsResponse{
		Assertions: out,
	}, c.w)
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
	if err := c.s.saveAccount(c.item, c.save, desc, c.r, c.id.Subject, c.tx); err != nil {
		return err
	}
	return nil
}

// HTTP handler for  "/identity/v1alpha/{realm}/admin/tokens"
func (s *Service) adminTokenMetadataFactory() *common.HandlerFactory {
	return &common.HandlerFactory{
		TypeName:            "tokens",
		PathPrefix:          adminTokenMetadataPath,
		HasNamedIdentifiers: false,
		NewHandler: func(w http.ResponseWriter, r *http.Request) common.HandlerInterface {
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
	return common.GetRequest(h.input, h.r)
}

func (h *adminTokenMetadataHandler) Get(name string) error {
	item := h.item
	if len(item) == 0 {
		item = nil
	}
	common.SendResponse(&pb.TokensMetadataResponse{
		TokensMetadata: item,
	}, h.w)
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
