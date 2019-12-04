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
	"sort"
	"strconv"
	"strings"

	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc/status"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage"

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/ic/v1"
	spb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/scim/v2"
)

var (
	// As used by storage.BuildFilters(), this maps the SCIM data model
	// filter path names to a slice path of where the field exists in
	// the storage data model. SCIM names are expected to be lowercase.
	scimUserFilterMap = map[string]func(p proto.Message) string{
		"id": func(p proto.Message) string {
			return acctProto(p).GetProperties().Subject
		},
		"name.formatted": func(p proto.Message) string {
			return acctProto(p).GetProfile().Name
		},
		"name.givenname": func(p proto.Message) string {
			return acctProto(p).GetProfile().GivenName
		},
		"name.familyname": func(p proto.Message) string {
			return acctProto(p).GetProfile().FamilyName
		},
		"name.middlename": func(p proto.Message) string {
			return acctProto(p).GetProfile().MiddleName
		},
		"username": func(p proto.Message) string {
			return acctProto(p).GetProperties().Subject
		},
	}
)

//////////////////////////////////////////////////////////////////

func acctProto(p proto.Message) *pb.Account {
	acct, ok := p.(*pb.Account)
	if !ok {
		return &pb.Account{}
	}
	return acct
}

func (s *Service) scimMeFactory() *common.HandlerFactory {
	return &common.HandlerFactory{
		TypeName:            "user",
		PathPrefix:          scimMePath,
		HasNamedIdentifiers: false,
		IsAdmin:             false,
		NewHandler: func(w http.ResponseWriter, r *http.Request) common.HandlerInterface {
			return &scimMe{
				s: s,
				w: w,
				r: r,
			}
		},
	}
}

type scimMe struct {
	s    *Service
	w    http.ResponseWriter
	r    *http.Request
	user *scimUser
}

// Setup initializes the handler
func (h *scimMe) Setup(tx storage.Tx, isAdmin bool) (int, error) {
	h.user = &scimUser{
		s:     h.s,
		w:     h.w,
		r:     h.r,
		input: &spb.Patch{},
	}
	return h.user.Setup(tx, isAdmin)
}

// LookupItem returns true if the named object is found
func (h *scimMe) LookupItem(name string, vars map[string]string) bool {
	return h.user.LookupItem(h.user.id.Subject, vars)
}

// NormalizeInput transforms a request's object to standard form, as needed
func (h *scimMe) NormalizeInput(name string, vars map[string]string) error {
	return h.user.NormalizeInput(name, vars)
}

// Get sends a GET method response
func (h *scimMe) Get(name string) error {
	return h.user.Get(name)
}

// Post receives a POST method request
func (h *scimMe) Post(name string) error {
	return h.user.Post(name)
}

// Put receives a PUT method request
func (h *scimMe) Put(name string) error {
	return h.user.Put(name)
}

// Patch receives a PATCH method request
func (h *scimMe) Patch(name string) error {
	return h.user.Patch(name)
}

// Remove receives a DELETE method request
func (h *scimMe) Remove(name string) error {
	return h.user.Remove(name)
}

// CheckIntegrity provides an opportunity to check the result of any changes
func (h *scimMe) CheckIntegrity() *status.Status {
	return h.user.CheckIntegrity()
}

// Save can save any valid changes that occured during the request
func (h *scimMe) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return h.user.Save(tx, name, vars, desc, typeName)
}

//////////////////////////////////////////////////////////////////

func (s *Service) scimUserFactory() *common.HandlerFactory {
	return &common.HandlerFactory{
		TypeName:            "user",
		PathPrefix:          scimUserPath,
		HasNamedIdentifiers: true,
		IsAdmin:             false,
		NewHandler: func(w http.ResponseWriter, r *http.Request) common.HandlerInterface {
			return &scimUser{
				s:     s,
				w:     w,
				r:     r,
				input: &spb.Patch{},
			}
		},
	}
}

type scimUser struct {
	s     *Service
	w     http.ResponseWriter
	r     *http.Request
	item  *pb.Account
	input *spb.Patch
	save  *pb.Account
	id    *ga4gh.Identity
	tx    storage.Tx
}

// Setup initializes the handler
func (h *scimUser) Setup(tx storage.Tx, isAdmin bool) (int, error) {
	_, _, id, status, err := h.s.handlerSetup(tx, isAdmin, h.r, noScope, h.input)
	h.id = id
	h.tx = tx
	if id == nil || !h.s.permissions.IsAdmin(id) && !hasScopes("account_admin", id.Scope, false) {
		return http.StatusUnauthorized, fmt.Errorf("unauthorized")
	}
	return status, err
}

// LookupItem returns true if the named object is found
func (h *scimUser) LookupItem(name string, vars map[string]string) bool {
	if _, err := h.s.permissions.CheckSubjectOrAdmin(h.id, name); err != nil {
		return false
	}
	realm := getRealm(h.r)
	acct := &pb.Account{}
	if _, err := h.s.singleRealmReadTx(storage.AccountDatatype, realm, storage.DefaultUser, name, storage.LatestRev, acct, h.tx); err != nil {
		return false
	}
	h.item = acct
	return true
}

// NormalizeInput transforms a request's object to standard form, as needed
func (h *scimUser) NormalizeInput(name string, vars map[string]string) error {
	if h.r.Method != http.MethodPatch {
		return nil
	}

	if len(h.input.Schemas) != 1 || h.input.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:PatchOp" {
		return fmt.Errorf("PATCH requires schemas set to only be %q", "urn:ietf:params:scim:api:messages:2.0:PatchOp")
	}

	return nil
}

// Get sends a GET method response
func (h *scimUser) Get(name string) error {
	return common.SendResponse(h.s.newScimUser(h.item, getRealm(h.r)), h.w)
}

// Post receives a POST method request
func (h *scimUser) Post(name string) error {
	return fmt.Errorf("POST not allowed")
}

// Put receives a PUT method request
func (h *scimUser) Put(name string) error {
	return fmt.Errorf("PUT not allowed")
}

// Patch receives a PATCH method request
func (h *scimUser) Patch(name string) error {
	h.save = &pb.Account{}
	proto.Merge(h.save, h.item)
	for i, patch := range h.input.Operations {
		src := patch.Value
		var dst *string
		switch patch.Path {
		case "active":
			// TODO: support for boolean input for "active" field instead of strings
			switch {
			case (patch.Op == "remove" && len(src) == 0) || (patch.Op == "replace" && src == "false"):
				h.save.State = storage.StateDisabled

			case src == "true" && (patch.Op == "add" || patch.Op == "replace"):
				h.save.State = storage.StateActive

			default:
				return fmt.Errorf("invalid active operation %q or value %q", patch.Op, patch.Value)
			}

		case "name.formatted":
			dst = &h.save.Profile.Name
			if patch.Op == "remove" {
				return fmt.Errorf("operation %d: cannot set %q to an empty value", i, patch.Path)
			}

		case "name.familyName":
			dst = &h.save.Profile.FamilyName

		case "name.givenName":
			dst = &h.save.Profile.GivenName

		case "name.middleName":
			dst = &h.save.Profile.MiddleName

		default:
			return fmt.Errorf("operation %d: invalid path %q", i, patch.Path)
		}
		if patch.Op != "remove" && len(src) == 0 {
			return fmt.Errorf("operation %d: cannot set an empty value", i)
		}
		if dst == nil {
			continue
		}
		switch patch.Op {
		case "add":
			fallthrough
		case "replace":
			*dst = src
		case "remove":
			*dst = ""
		default:
			return fmt.Errorf("operation %d: invalid op %q", i, patch.Op)
		}
	}
	return common.SendResponse(h.s.newScimUser(h.save, getRealm(h.r)), h.w)
}

// Remove receives a DELETE method request
func (h *scimUser) Remove(name string) error {
	h.save = &pb.Account{}
	proto.Merge(h.save, h.item)
	for _, link := range h.save.ConnectedAccounts {
		if link.Properties == nil || len(link.Properties.Subject) == 0 {
			continue
		}
		if err := h.s.removeAccountLookup(link.LinkRevision, getRealm(h.r), link.Properties.Subject, h.r, h.id, h.tx); err != nil {
			return fmt.Errorf("service dependencies not available; try again later")
		}
	}
	h.save.ConnectedAccounts = []*pb.ConnectedAccount{}
	h.save.State = "DELETED"
	return nil
}

// CheckIntegrity provides an opportunity to check the result of any changes
func (h *scimUser) CheckIntegrity() *status.Status {
	return nil
}

// Save can save any valid changes that occured during the request
func (h *scimUser) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	if h.save == nil {
		return nil
	}
	return h.s.saveAccount(h.item, h.save, desc, h.r, h.id.Subject, h.tx)
}

//////////////////////////////////////////////////////////////////

func (s *Service) scimUsersFactory() *common.HandlerFactory {
	return &common.HandlerFactory{
		TypeName:            "users",
		PathPrefix:          scimUsersPath,
		HasNamedIdentifiers: true,
		IsAdmin:             true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) common.HandlerInterface {
			return &scimUsers{
				s: s,
				w: w,
				r: r,
			}
		},
	}
}

type scimUsers struct {
	s  *Service
	w  http.ResponseWriter
	r  *http.Request
	id *ga4gh.Identity
	tx storage.Tx
}

// Setup initializes the handler
func (h *scimUsers) Setup(tx storage.Tx, isAdmin bool) (int, error) {
	_, _, id, status, err := h.s.handlerSetup(tx, isAdmin, h.r, noScope, nil)
	h.id = id
	h.tx = tx
	return status, err
}

// LookupItem returns true if the named object is found
func (h *scimUsers) LookupItem(name string, vars map[string]string) bool {
	return true
}

// NormalizeInput transforms a request's object to standard form, as needed
func (h *scimUsers) NormalizeInput(name string, vars map[string]string) error {
	return nil
}

// Get sends a GET method response
func (h *scimUsers) Get(name string) error {
	filters, err := storage.BuildFilters(common.GetParam(h.r, "filter"), scimUserFilterMap)
	if err != nil {
		return err
	}
	m := make(map[string]map[string]proto.Message)
	if err := h.s.store.MultiReadTx(storage.AccountDatatype, getRealm(h.r), storage.DefaultUser, filters, m, &pb.Account{}, h.tx); err != nil {
		return err
	}
	accts := make(map[string]*pb.Account)
	subjects := []string{}
	for _, u := range m {
		for _, v := range u {
			if acct, ok := v.(*pb.Account); ok {
				accts[acct.Properties.Subject] = acct
				subjects = append(subjects, acct.Properties.Subject)
			}
		}
	}
	sort.Strings(subjects)
	realm := getRealm(h.r)
	list := []*spb.User{}
	for _, sub := range subjects {
		list = append(list, h.s.newScimUser(accts[sub], realm))
	}

	count := uint32(len(subjects))
	resp := &spb.ListUsersResponse{
		Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		TotalResults: count,
		ItemsPerPage: count,
		StartIndex:   0,
		Resources:    list,
	}
	return common.SendResponse(resp, h.w)
}

// Post receives a POST method request
func (h *scimUsers) Post(name string) error {
	return fmt.Errorf("POST not allowed")
}

// Put receives a PUT method request
func (h *scimUsers) Put(name string) error {
	return fmt.Errorf("PUT not allowed")
}

// Patch receives a PATCH method request
func (h *scimUsers) Patch(name string) error {
	return fmt.Errorf("PATCH not allowed")
}

// Remove receives a DELETE method request
func (h *scimUsers) Remove(name string) error {
	return fmt.Errorf("DELETE not allowed")
}

// CheckIntegrity provides an opportunity to check the result of any changes
func (h *scimUsers) CheckIntegrity() *status.Status {
	return nil
}

// Save can save any valid changes that occured during the request
func (h *scimUsers) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return nil
}

func (s *Service) newScimUser(acct *pb.Account, realm string) *spb.User {
	var emails []*spb.Attribute
	for _, ca := range acct.ConnectedAccounts {
		emails = append(emails, &spb.Attribute{
			Value:             ca.Properties.Email,
			ExtensionVerified: ca.Properties.EmailVerified,
		})
	}
	return &spb.User{
		Schemas:    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		Id:         acct.Properties.Subject,
		ExternalId: acct.Properties.Subject,
		Meta: &spb.ResourceMetadata{
			ResourceType: "User",
			Created:      common.TimestampString(int64(acct.Properties.Created)),
			LastModified: common.TimestampString(int64(acct.Properties.Modified)),
			Location:     s.getDomainURL() + strings.ReplaceAll(scimUsersPath, common.RealmVariable, realm) + "/" + acct.Properties.Subject,
			Version:      strconv.FormatInt(acct.Revision, 10),
		},
		Name: &spb.Name{
			Formatted:  acct.Profile.Name,
			FamilyName: acct.Profile.FamilyName,
			GivenName:  acct.Profile.GivenName,
			MiddleName: acct.Profile.MiddleName,
		},
		UserName: acct.Properties.Subject,
		Emails:   emails,
		Active:   acct.State == storage.StateActive,
	}
}
