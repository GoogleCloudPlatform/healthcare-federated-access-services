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

package scim

import (
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"regexp"
	"sort"
	"strings"

	"github.com/golang/protobuf/jsonpb" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/handlerfactory" /* copybara-comment: handlerfactory */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/strutil" /* copybara-comment: strutil */

	spb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/scim/v2" /* copybara-comment: go_proto */
)

var (
	scimGroupFilterMap = map[string]func(p proto.Message) string{
		"displayName": func(p proto.Message) string {
			return groupProto(p).DisplayName
		},
		"id": func(p proto.Message) string {
			return groupProto(p).Id
		},
		"$ref": func(p proto.Message) string {
			return groupRef(groupProto(p))
		},
	}

	scimMemberFilterMap = map[string]func(p proto.Message) string{
		"member.issuer": func(p proto.Message) string {
			return memberProto(p).ExtensionIssuer
		},
		"member.subject": func(p proto.Message) string {
			return memberProto(p).ExtensionSubject
		},
		"member.type": func(p proto.Message) string {
			return memberProto(p).Type
		},
		"member.value": func(p proto.Message) string {
			return memberProto(p).Value
		},
		"$ref": func(p proto.Message) string {
			return memberRef(memberProto(p))
		},
	}

	groupMemberRegexps = map[string]*regexp.Regexp{
		"value": regexp.MustCompile(`[^/\\@]+@[^/\\@]+\.[^/\\@]{2,20}$`),
	}
	memberPathRE = regexp.MustCompile(`^members\[\$ref eq "(.*)"\]$`)
)

////////////////////////////////////////////////////////////

// GroupFactory creates handlers for group requests.
func GroupFactory(store storage.Store, groupPath string) *handlerfactory.HandlerFactory {
	return &handlerfactory.HandlerFactory{
		TypeName:            "group",
		PathPrefix:          groupPath,
		HasNamedIdentifiers: false,
		NewHandler: func(r *http.Request) handlerfactory.HandlerInterface {
			return NewGroupHandler(store, r)
		},
	}
}

// GroupHandler handles SCIM group requests.
type GroupHandler struct {
	r     *http.Request
	item  *spb.Group
	save  *spb.Group
	input *spb.Group
	patch *spb.Patch
	store storage.Store
	tx    storage.Tx
}

// NewGroupHandler handles one SCIM group request.
func NewGroupHandler(store storage.Store, r *http.Request) *GroupHandler {
	return &GroupHandler{
		store: store,
		r:     r,
		item:  &spb.Group{},
	}
}

// Setup sets up the handler.
func (h *GroupHandler) Setup(tx storage.Tx) (int, error) {
	h.r.ParseForm()
	switch h.r.Method {
	case http.MethodPost:
		fallthrough
	case http.MethodPut:
		h.input = &spb.Group{}
		if err := jsonpb.Unmarshal(h.r.Body, h.input); err != nil && err != io.EOF {
			return http.StatusBadRequest, err
		}
	case http.MethodPatch:
		h.patch = &spb.Patch{}
		if err := jsonpb.Unmarshal(h.r.Body, h.patch); err != nil && err != io.EOF {
			return http.StatusBadRequest, err
		}
	}
	h.tx = tx
	return http.StatusOK, nil
}

// LookupItem looks up the item in the storage layer.
func (h *GroupHandler) LookupItem(name string, vars map[string]string) bool {
	if err := h.store.ReadTx(storage.GroupDatatype, getRealm(h.r), name, storage.DefaultID, storage.LatestRev, h.item, h.tx); err != nil {
		return false
	}
	return true
}

// NormalizeInput sets up basic structure of request input objects if absent.
func (h *GroupHandler) NormalizeInput(name string, vars map[string]string) error {
	switch h.r.Method {
	case http.MethodPatch:
		if len(h.patch.Schemas) != 1 || h.patch.Schemas[0] != scimPatchSchema {
			return fmt.Errorf("PATCH requires schemas set to only be %q", scimPatchSchema)
		}
	case http.MethodPost:
		fallthrough
	case http.MethodPut:
		if len(h.input.Schemas) != 1 || h.input.Schemas[0] != scimGroupSchema {
			return fmt.Errorf("%s requires schemas set to only be %q", strings.ToUpper(h.r.Method), scimGroupSchema)
		}
	}

	if h.input == nil {
		return nil
	}

	switch {
	case h.input.Id == "":
		h.input.Id = name
	case h.input.Id != name:
		return fmt.Errorf("group %q id %q mismatch: id must match group name", name, h.input.Id)
	}
	for i, member := range h.input.Members {
		if member == nil {
			return fmt.Errorf("group %q member %d: cannot have empty members", name, i)
		}
		if err := h.normalizeMember(member); err != nil {
			return fmt.Errorf("group %q member %d: %v", name, i, err)
		}
	}
	return nil
}

// Get is a GET request.
func (h *GroupHandler) Get(name string) (proto.Message, error) {
	filters, err := storage.BuildFilters(httputil.QueryParam(h.r, "filter"), scimMemberFilterMap)
	if err != nil {
		return nil, err
	}
	// "startIndex" is a 1-based starting location, to be converted to an offset for the query.
	start := httputil.QueryParamInt(h.r, "startIndex")
	if start == 0 {
		start = 1
	}
	offset := start - 1
	// "count" is the number of results desired on this request's page.
	max := httputil.QueryParamInt(h.r, "count")
	if len(httputil.QueryParam(h.r, "count")) == 0 {
		max = storage.DefaultPageSize
	}

	m := make(map[string]map[string]proto.Message)
	_, err = h.store.MultiReadTx(storage.GroupMemberDatatype, getRealm(h.r), name, filters, offset, max, m, &spb.Member{}, h.tx)
	if err != nil {
		return nil, err
	}
	members := make(map[string]*spb.Member)
	keys := []string{}
	for _, u := range m {
		for _, v := range u {
			if member, ok := v.(*spb.Member); ok {
				member.Ref = member.Value
				members[member.Value] = member
				keys = append(keys, member.Value)
			}
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		h.item.Members = append(h.item.Members, members[key])
	}
	return h.item, nil
}

// Post is a POST request.
func (h *GroupHandler) Post(name string) (proto.Message, error) {
	h.save = h.input
	for _, member := range h.save.Members {
		if err := httputil.CheckName("value", member.Value, groupMemberRegexps); err != nil {
			return nil, fmt.Errorf("group member %q email format check failed: %v", member.Value, err)
		}
		if err := h.store.WriteTx(storage.GroupMemberDatatype, getRealm(h.r), name, member.Value, storage.LatestRev, member, nil, h.tx); err != nil {
			return nil, fmt.Errorf("writing group member %q: %v", member.Value, err)
		}
	}
	return nil, nil
}

// Put is a PUT request.
func (h *GroupHandler) Put(name string) (proto.Message, error) {
	// Clean up existing membership
	if _, err := h.Remove(name); err != nil {
		return nil, err
	}
	return h.Post(name)
}

// Patch is a PATCH request.
func (h *GroupHandler) Patch(name string) (proto.Message, error) {
	h.save = &spb.Group{}
	proto.Merge(h.save, h.item)
	for i, patch := range h.patch.Operations {
		path := patch.Path
		if memberPathRE.MatchString(path) {
			path = "member"
		}
		src := ""
		var dst *string
		switch path {
		case "displayName":
			src = patchSource(patch.Value)
			dst = &h.save.DisplayName
			if patch.Op == "remove" || len(src) == 0 {
				return nil, fmt.Errorf("operation %d failed: cannot set %q to an empty value", i, path)
			}

		case "members":
			if patch.Op != "add" {
				return nil, fmt.Errorf("operation %d failed: op %q not valid on path %q", i, patch.Op, path)
			}
			member, err := h.patchMember(patch.Object)
			if err != nil {
				return nil, fmt.Errorf("operation %d failed: %v", i, err)
			}
			if err := h.store.WriteTx(storage.GroupMemberDatatype, getRealm(h.r), name, member.Value, storage.LatestRev, member, nil, h.tx); err != nil {
				return nil, fmt.Errorf("writing group member %q: %v", member.Value, err)
			}

		case "member":
			if patch.Op != "remove" {
				return nil, fmt.Errorf("operation %d failed: op %q not valid on path %q", i, patch.Op, patch.Path)
			}
			match := memberPathRE.FindStringSubmatch(patch.Path)
			if len(match) < 2 {
				return nil, fmt.Errorf("operation %d failed: invalid member path %q", i, patch.Path)
			}
			memberName := match[1]
			if err := h.store.DeleteTx(storage.GroupMemberDatatype, getRealm(h.r), name, memberName, storage.LatestRev, h.tx); err != nil {
				if storage.ErrNotFound(err) {
					return nil, fmt.Errorf("operation %d failed: %q is not a member of the group", i, memberName)
				}
				return nil, fmt.Errorf("operation %d failed: removing group member %q: %v", i, memberName, err)
			}

		default:
			return nil, fmt.Errorf("operation %d failed: invalid path %q", i, path)
		}
		if dst == nil {
			continue
		}
		if patch.Op != "remove" && len(src) == 0 {
			return nil, fmt.Errorf("operation %d failed: cannot set an empty value", i)
		}
		switch patch.Op {
		case "add":
			fallthrough
		case "replace":
			*dst = src
		case "remove":
			*dst = ""
		default:
			return nil, fmt.Errorf("operation %d: invalid op %q", i, patch.Op)
		}
	}
	// Output the new result: Get() will return contents from h.item.
	h.item = h.save
	return h.Get(name)
}

// Remove is a DELETE request.
func (h *GroupHandler) Remove(name string) (proto.Message, error) {
	if err := h.store.MultiDeleteTx(storage.GroupMemberDatatype, getRealm(h.r), name, h.tx); err != nil {
		return nil, err
	}
	return nil, h.store.DeleteTx(storage.GroupDatatype, getRealm(h.r), name, storage.DefaultID, storage.LatestRev, h.tx)
}

// CheckIntegrity checks that any modifications make sense before applying them.
func (h *GroupHandler) CheckIntegrity() *status.Status {
	return nil
}

// Save will save any modifications done for the request.
func (h *GroupHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	if h.save == nil {
		return nil
	}
	h.save.Members = nil // members are stored separately.
	return h.store.WriteTx(storage.GroupDatatype, getRealm(h.r), name, storage.DefaultID, storage.LatestRev, h.save, nil, h.tx)
}

func (h *GroupHandler) patchMember(object map[string]string) (*spb.Member, error) {
	if object == nil {
		return nil, fmt.Errorf("member not provided")
	}
	typ := object["type"]
	if typ == "" {
		typ = "User"
	}
	member := &spb.Member{
		Type:             typ,
		Value:            object["value"],
		ExtensionIssuer:  object["issuer"],
		ExtensionSubject: object["subject"],
	}
	if err := h.normalizeMember(member); err != nil {
		return nil, fmt.Errorf("invalid member format: %v", err)
	}
	return member, nil
}

func (h *GroupHandler) normalizeMember(member *spb.Member) error {
	switch member.Type {
	case "User":
	case "":
		member.Type = "User"
	default:
		return fmt.Errorf("invalid member type %q", member.Type)
	}
	email, err := mail.ParseAddress(member.Value)
	if err != nil {
		return fmt.Errorf("invalid member email value %q: %v", member.Value, err)
	}
	member.Value = email.Address
	member.Display = strings.TrimSpace(email.Name)
	if member.Display == "" {
		member.Display = member.Value
	}
	if member.ExtensionIssuer != "" && !strutil.IsURL(member.ExtensionIssuer) {
		return fmt.Errorf("invalid member issuer %q", member.ExtensionIssuer)
	}
	if member.ExtensionIssuer != "" && len(member.ExtensionIssuer) > 256 {
		return fmt.Errorf("member issuer %q exceeds maximum length", member.ExtensionIssuer)
	}
	if member.ExtensionSubject != "" && len(member.ExtensionSubject) > 60 {
		return fmt.Errorf("member subject %q exceeds maximum length", member.ExtensionSubject)
	}
	return nil
}

func memberProto(p proto.Message) *spb.Member {
	member, ok := p.(*spb.Member)
	if !ok {
		return &spb.Member{}
	}
	return member
}

func groupProto(p proto.Message) *spb.Group {
	group, ok := p.(*spb.Group)
	if !ok {
		return &spb.Group{}
	}
	return group
}

func groupRef(group *spb.Group) string {
	return "group/" + group.Id
}

func memberRef(member *spb.Member) string {
	return "member/" + member.Value
}
