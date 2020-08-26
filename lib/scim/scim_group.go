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
	"strconv"
	"strings"

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/golang/protobuf/jsonpb" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/errutil" /* copybara-comment: errutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/handlerfactory" /* copybara-comment: handlerfactory */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/strutil" /* copybara-comment: strutil */

	spb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/scim/v2" /* copybara-comment: go_proto */
)

var (
	scimGroupFilterMap = map[string]func(p proto.Message) string{
		"displayname": func(p proto.Message) string {
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
		"member.display": func(p proto.Message) string {
			return memberProto(p).Display
		},
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

	scimGroupsFilterMap = map[string]func(p proto.Message) string{
		"displayname": func(p proto.Message) string {
			return groupProto(p).DisplayName
		},
		"id": func(p proto.Message) string {
			return groupProto(p).Id
		},
		"externalid": func(p proto.Message) string {
			return groupProto(p).ExternalId
		},
	}

	memberPathRE = regexp.MustCompile(`^members\[\$ref eq "(.*)"\]$`)
)

////////////////////////////////////////////////////////////

// GroupFactory creates handlers for group requests.
func GroupFactory(store storage.Store, groupPath string) *handlerfactory.Options {
	return &handlerfactory.Options{
		TypeName:            "group",
		PathPrefix:          groupPath,
		HasNamedIdentifiers: true,
		Service: func() handlerfactory.Service {
			return NewGroupHandler(store)
		},
	}
}

// GroupHandler handles SCIM group requests.
type GroupHandler struct {
	item  *spb.Group
	save  *spb.Group
	input *spb.Group
	patch *spb.Patch
	scim  *Scim
	store storage.Store
	tx    storage.Tx
}

// NewGroupHandler handles one SCIM group request.
func NewGroupHandler(store storage.Store) *GroupHandler {
	return &GroupHandler{
		store: store,
		scim:  New(store),
		item:  &spb.Group{},
	}
}

// Setup sets up the handler.
func (h *GroupHandler) Setup(r *http.Request, tx storage.Tx) (int, error) {
	r.ParseForm()
	switch r.Method {
	case http.MethodPost:
		fallthrough
	case http.MethodPut:
		h.input = &spb.Group{}
		if err := jsonpb.Unmarshal(r.Body, h.input); err != nil && err != io.EOF {
			return http.StatusBadRequest, err
		}
	case http.MethodPatch:
		h.patch = &spb.Patch{}
		if err := jsonpb.Unmarshal(r.Body, h.patch); err != nil && err != io.EOF {
			return http.StatusBadRequest, err
		}
	}
	h.tx = tx
	return http.StatusOK, nil
}

// LookupItem looks up the item in the storage layer.
func (h *GroupHandler) LookupItem(r *http.Request, name string, vars map[string]string) bool {
	group, err := h.scim.LoadGroup(name, getRealm(r), h.tx)
	if err != nil || group == nil {
		return false
	}

	h.item = group
	return true
}

// NormalizeInput sets up basic structure of request input objects if absent.
func (h *GroupHandler) NormalizeInput(r *http.Request, name string, vars map[string]string) error {
	switch r.Method {
	case http.MethodPatch:
		if len(h.patch.Schemas) != 1 || h.patch.Schemas[0] != scimPatchSchema {
			return fmt.Errorf("PATCH requires schemas set to only be %q", scimPatchSchema)
		}
	case http.MethodPost:
		fallthrough
	case http.MethodPut:
		if len(h.input.Schemas) != 1 || h.input.Schemas[0] != scimGroupSchema {
			return fmt.Errorf("%s requires schemas set to only be %q", strings.ToUpper(r.Method), scimGroupSchema)
		}
	}

	if h.input == nil {
		return nil
	}

	switch {
	case h.input.Id == "":
		h.input.Id = name
	case h.input.Id != name:
		return errutil.NewError(codes.InvalidArgument, errutil.ErrorPath("scim", "groups", name), fmt.Sprintf("value must not be empty"))
	}
	for i, member := range h.input.Members {
		if member == nil {
			return errutil.NewIndexError(codes.InvalidArgument, errutil.ErrorPath("scim", "groups", name), i, fmt.Sprintf("member must not be empty"))
		}
		if err := h.normalizeMember(member, name, i); err != nil {
			return err
		}
	}
	return nil
}

// Get is a GET request.
func (h *GroupHandler) Get(r *http.Request, name string) (proto.Message, error) {
	filters, err := storage.BuildFilters(httputils.QueryParam(r, "filter"), scimMemberFilterMap)
	if err != nil {
		return nil, err
	}
	// "startIndex" is a 1-based starting location, to be converted to an offset for the query.
	start := httputils.QueryParamInt(r, "startIndex")
	if start == 0 {
		start = 1
	}
	offset := start - 1
	// "count" is the number of results desired on this request's page.
	max := httputils.QueryParamInt(r, "count")
	if len(httputils.QueryParam(r, "count")) == 0 {
		max = storage.DefaultPageSize
	}

	results, err := h.store.MultiReadTx(storage.GroupMemberDatatype, getRealm(r), name, storage.MatchAllIDs, filters, offset, max, &spb.Member{}, h.tx)
	if err != nil {
		return nil, err
	}
	members := make(map[string]*spb.Member)
	keys := []string{}
	for _, entry := range results.Entries {
		if member, ok := entry.Item.(*spb.Member); ok {
			member.Ref = member.Value
			members[member.Value] = member
			keys = append(keys, member.Value)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		h.item.Members = append(h.item.Members, members[key])
	}
	return h.item, nil
}

// Post is a POST request.
func (h *GroupHandler) Post(r *http.Request, name string) (proto.Message, error) {
	h.save = h.input
	for i, member := range h.save.Members {
		if err := h.normalizeMember(member, name, i); err != nil {
			return nil, err
		}
		if err := h.store.WriteTx(storage.GroupMemberDatatype, getRealm(r), name, member.Value, storage.LatestRev, member, nil, h.tx); err != nil {
			return nil, fmt.Errorf("writing group member %q: %v", member.Value, err)
		}
	}
	return nil, nil
}

// Put is a PUT request.
func (h *GroupHandler) Put(r *http.Request, name string) (proto.Message, error) {
	// Clean up existing membership
	if _, err := h.Remove(r, name); err != nil {
		return nil, err
	}
	return h.Post(r, name)
}

// Patch is a PATCH request.
func (h *GroupHandler) Patch(r *http.Request, name string) (proto.Message, error) {
	h.save = &spb.Group{}
	proto.Merge(h.save, h.item)
	memberCounter := 0
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
				return nil, errutil.NewIndexError(codes.InvalidArgument, errutil.ErrorPath("scim", "groups", name, path), i, fmt.Sprintf("value must not be empty"))
			}

		case "members":
			if patch.Op != "add" {
				return nil, errutil.NewIndexError(codes.InvalidArgument, errutil.ErrorPath("scim", "groups", name, path), i, fmt.Sprintf("op %q is not valid", patch.Op))
			}
			member, err := h.patchMember(patch.Object, name, memberCounter)
			if err != nil {
				return nil, err
			}
			memberCounter++
			if err := h.store.WriteTx(storage.GroupMemberDatatype, getRealm(r), name, member.Value, storage.LatestRev, member, nil, h.tx); err != nil {
				return nil, errutil.NewIndexError(codes.InvalidArgument, errutil.ErrorPath("scim", "groups", name, path), i, err.Error())
			}

		case "member":
			if patch.Op != "remove" {
				return nil, errutil.NewIndexError(codes.InvalidArgument, errutil.ErrorPath("scim", "groups", name, path), i, fmt.Sprintf("op %q is not valid", patch.Op))
			}
			match := memberPathRE.FindStringSubmatch(patch.Path)
			if len(match) < 2 {
				return nil, errutil.NewIndexError(codes.InvalidArgument, errutil.ErrorPath("scim", "groups", name, path), i, fmt.Sprintf("invalid member path %q", patch.Path))
			}
			memberName := match[1]
			if err := h.store.DeleteTx(storage.GroupMemberDatatype, getRealm(r), name, memberName, storage.LatestRev, h.tx); err != nil {
				if storage.ErrNotFound(err) {
					return nil, errutil.NewIndexError(codes.InvalidArgument, errutil.ErrorPath("scim", "groups", name, path), i, fmt.Sprintf("%q is not a member of the group", memberName))
				}
				return nil, errutil.NewIndexError(codes.InvalidArgument, errutil.ErrorPath("scim", "groups", name, path), i, err.Error())
			}

		default:
			return nil, errutil.NewIndexError(codes.InvalidArgument, errutil.ErrorPath("scim", "groups", name, path), i, fmt.Sprintf("invalid path %q", patch.Path))
		}
		if dst == nil {
			continue
		}
		if patch.Op != "remove" && len(src) == 0 {
			return nil, errutil.NewIndexError(codes.InvalidArgument, errutil.ErrorPath("scim", "groups", name, path), i, fmt.Sprintf("cannot set an empty value"))
		}
		switch patch.Op {
		case "add":
			fallthrough
		case "replace":
			*dst = src
		case "remove":
			*dst = ""
		default:
			return nil, errutil.NewIndexError(codes.InvalidArgument, errutil.ErrorPath("scim", "groups", name, path), i, fmt.Sprintf("invalid op %q", patch.Op))
		}
	}
	// Output the new result: Get() will return contents from h.item with the latest edits from h.save.
	// Needs a deep copy since h.save as the item saved will not include members once Save() is called
	// but the item returned to the client will include members.
	h.item = proto.Clone(h.save).(*spb.Group)
	return h.Get(r, name)
}

// Remove is a DELETE request.
func (h *GroupHandler) Remove(r *http.Request, name string) (proto.Message, error) {
	if err := h.store.MultiDeleteTx(storage.GroupMemberDatatype, getRealm(r), name, h.tx); err != nil {
		return nil, err
	}
	return nil, h.store.DeleteTx(storage.GroupDatatype, getRealm(r), name, storage.DefaultID, storage.LatestRev, h.tx)
}

// CheckIntegrity checks that any modifications make sense before applying them.
func (h *GroupHandler) CheckIntegrity(*http.Request) *status.Status {
	return nil
}

// Save will save any modifications done for the request.
func (h *GroupHandler) Save(r *http.Request, tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	if h.save == nil {
		return nil
	}
	h.save.Members = nil // members are stored separately.
	return h.store.WriteTx(storage.GroupDatatype, getRealm(r), name, storage.DefaultID, storage.LatestRev, h.save, nil, h.tx)
}

func (h *GroupHandler) patchMember(object map[string]string, name string, idx int) (*spb.Member, error) {
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
	if err := h.normalizeMember(member, name, idx); err != nil {
		return nil, err
	}
	return member, nil
}

func (h *GroupHandler) normalizeMember(member *spb.Member, name string, idx int) error {
	switch member.Type {
	case "User":
	case "":
		member.Type = "User"
	default:
		return errutil.NewIndexError(codes.InvalidArgument, errutil.ErrorPath("scim", "groups", name, "members", strconv.Itoa(idx), "type"), idx, "invalid member type")
	}
	email, err := mail.ParseAddress(member.Value)
	if err != nil {
		return errutil.NewIndexError(codes.InvalidArgument, errutil.ErrorPath("scim", "groups", name, "members", strconv.Itoa(idx), "value"), idx, fmt.Sprintf("%q must be an email address", member.Value))
	}
	member.Value = email.Address
	if member.Display == "" && email.Name != "" {
		member.Display = strings.TrimSpace(email.Name)
	}
	if member.Display != "" && strings.Contains(member.Display, "@") {
		// Do not accept email addresses as the display name.
		// Reject when a different email address, or remove display field when it repeats the value field.
		if member.Display != member.Value {
			return errutil.NewIndexError(codes.InvalidArgument, errutil.ErrorPath("scim", "groups", name, "members", strconv.Itoa(idx), "display"), idx, "display name as an email address not allowed")
		}
		member.Display = ""
	}
	if member.ExtensionIssuer != "" && !strutil.IsURL(member.ExtensionIssuer) {
		return errutil.NewIndexError(codes.InvalidArgument, errutil.ErrorPath("scim", "groups", name, "members", strconv.Itoa(idx), "issuer"), idx, fmt.Sprintf("invalid member issuer %q", member.ExtensionIssuer))
	}
	if member.ExtensionIssuer != "" && len(member.ExtensionIssuer) > 256 {
		return errutil.NewIndexError(codes.InvalidArgument, errutil.ErrorPath("scim", "groups", name, "members", strconv.Itoa(idx), "issuer"), idx, fmt.Sprintf("member issuer %q exceeds maximum length", member.ExtensionIssuer))
	}
	if member.ExtensionSubject != "" && len(member.ExtensionSubject) > 60 {
		return errutil.NewIndexError(codes.InvalidArgument, errutil.ErrorPath("scim", "groups", name, "members", strconv.Itoa(idx), "subject"), idx, fmt.Sprintf("member subject %q exceeds maximum length", member.ExtensionSubject))
	}
	return nil
}

////////////////////////////////////////////////////////////

// GroupsFactory creates handlers for group requests.
func GroupsFactory(store storage.Store, path string) *handlerfactory.Options {
	return &handlerfactory.Options{
		TypeName:            "groups",
		PathPrefix:          path,
		HasNamedIdentifiers: false,
		Service: func() handlerfactory.Service {
			return NewGroupsHandler(store)
		},
	}
}

// GroupsHandler handles SCIM group requests.
type GroupsHandler struct {
	scim  *Scim
	store storage.Store
	tx    storage.Tx
}

// NewGroupsHandler handles the SCIM groups request.
func NewGroupsHandler(store storage.Store) *GroupsHandler {
	return &GroupsHandler{
		store: store,
		scim:  New(store),
	}
}

// Setup sets up the handler.
func (h *GroupsHandler) Setup(r *http.Request, tx storage.Tx) (int, error) {
	r.ParseForm()
	h.tx = tx
	return http.StatusOK, nil
}

// LookupItem returns true if the named object is found.
func (h *GroupsHandler) LookupItem(r *http.Request, name string, vars map[string]string) bool {
	return true
}

// NormalizeInput sets up basic structure of request input objects if absent.
func (h *GroupsHandler) NormalizeInput(r *http.Request, name string, vars map[string]string) error {
	return nil
}

// Get is a GET request.
func (h *GroupsHandler) Get(r *http.Request, name string) (proto.Message, error) {
	filters, err := storage.BuildFilters(httputils.QueryParam(r, "filter"), scimGroupsFilterMap)
	if err != nil {
		return nil, err
	}
	// "startIndex" is a 1-based starting location, to be converted to an offset for the query.
	start := httputils.QueryParamInt(r, "startIndex")
	if start == 0 {
		start = 1
	}
	offset := start - 1
	// "count" is the number of results desired on this request's page.
	max := httputils.QueryParamInt(r, "count")
	if len(httputils.QueryParam(r, "count")) == 0 {
		max = storage.DefaultPageSize
	}

	results, err := h.store.MultiReadTx(storage.GroupDatatype, getRealm(r), storage.MatchAllGroups, storage.MatchAllIDs, filters, offset, max, &spb.Group{}, h.tx)
	if err != nil {
		return nil, err
	}

	groups := make(map[string]*spb.Group)
	names := []string{}
	for _, entry := range results.Entries {
		if group, ok := entry.Item.(*spb.Group); ok {
			groups[group.Id] = group
			names = append(names, group.Id)
		}
	}
	sort.Strings(names)
	var list []*spb.Group
	for _, name := range names {
		list = append(list, groups[name])
	}

	resp := &spb.ListGroupsResponse{
		Schemas:      []string{scimListSchema},
		TotalResults: uint32(offset + results.MatchCount),
		ItemsPerPage: uint32(len(list)),
		StartIndex:   uint32(start),
		Resources:    list,
	}
	return resp, nil
}

// Post is a POST request.
func (h *GroupsHandler) Post(r *http.Request, name string) (proto.Message, error) {
	return nil, fmt.Errorf("POST not allowed")
}

// Put is a PUT request.
func (h *GroupsHandler) Put(r *http.Request, name string) (proto.Message, error) {
	return nil, fmt.Errorf("PUT not allowed")
}

// Patch is a PATCH request.
func (h *GroupsHandler) Patch(r *http.Request, name string) (proto.Message, error) {
	return nil, fmt.Errorf("PATCH not allowed")
}

// Remove is a DELETE request.
func (h *GroupsHandler) Remove(r *http.Request, name string) (proto.Message, error) {
	return nil, fmt.Errorf("DELETE not allowed")
}

// CheckIntegrity checks that any modifications make sense before applying them.
func (h *GroupsHandler) CheckIntegrity(*http.Request) *status.Status {
	return nil
}

// Save will save any modifications done for the request.
func (h *GroupsHandler) Save(r *http.Request, tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return nil
}

////////////////////////////////////////////////////////////

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
