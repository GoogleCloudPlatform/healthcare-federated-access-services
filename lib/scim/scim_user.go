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
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/golang/protobuf/jsonpb" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/auth" /* copybara-comment: auth */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/handlerfactory" /* copybara-comment: handlerfactory */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/strutil" /* copybara-comment: strutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/timeutil" /* copybara-comment: timeutil */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	spb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/scim/v2" /* copybara-comment: go_proto */
)

var (
	// As used by storage.BuildFilters(), this maps the SCIM data model
	// filter path names to a slice path of where the field exists in
	// the storage data model. SCIM names are expected to be the lowercase
	// version of the names from the SCIM spec.
	scimUserFilterMap = map[string]func(p proto.Message) string{
		"active": func(p proto.Message) string {
			if acctProto(p).State == storage.StateActive {
				return "true"
			}
			return "false"
		},
		"displayname": func(p proto.Message) string {
			return acctProto(p).GetProfile().Name
		},
		"emails": func(p proto.Message) string {
			list := []string{}
			for _, link := range acctProto(p).ConnectedAccounts {
				list = append(list, link.GetProperties().Email)
			}
			return strutil.JoinNonEmpty(list, " ")
		},
		"externalid": func(p proto.Message) string {
			return acctProto(p).GetProperties().Subject
		},
		"id": func(p proto.Message) string {
			return acctProto(p).GetProperties().Subject
		},
		"locale": func(p proto.Message) string {
			return acctProto(p).GetProfile().Locale
		},
		"preferredlanguage": func(p proto.Message) string {
			return acctProto(p).GetProfile().Locale
		},
		"name.formatted": func(p proto.Message) string {
			return formattedName(acctProto(p))
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
		"timezone": func(p proto.Message) string {
			return acctProto(p).GetProfile().ZoneInfo
		},
		"username": func(p proto.Message) string {
			return acctProto(p).GetProperties().Subject
		},
	}

	scimEmailFilterMap = map[string]func(p proto.Message) string{
		"$ref": func(p proto.Message) string {
			return emailRef(linkProto(p))
		},
		"value": func(p proto.Message) string {
			return linkProto(p).GetProperties().Email
		},
		"primary": func(p proto.Message) string {
			if linkProto(p).Primary {
				return "true"
			}
			return "false"
		},
	}

	emailPathRE = regexp.MustCompile(`^emails\[(.*)\](\.primary)?$`)
	photoPathRE = regexp.MustCompile(`^photos.*\.value$`)
)

//////////////////////////////////////////////////////////////////

func acctProto(p proto.Message) *cpb.Account {
	acct, ok := p.(*cpb.Account)
	if !ok {
		return &cpb.Account{}
	}
	return acct
}

func linkProto(p proto.Message) *cpb.ConnectedAccount {
	link, ok := p.(*cpb.ConnectedAccount)
	if !ok {
		return &cpb.ConnectedAccount{}
	}
	return link
}

// MeFactory creates SCIM /Me request handlers.
func MeFactory(store storage.Store, domainURL, path string) *handlerfactory.HandlerFactory {
	return &handlerfactory.HandlerFactory{
		TypeName:            "user",
		PathPrefix:          path,
		HasNamedIdentifiers: false,
		NewHandler: func(w http.ResponseWriter, r *http.Request) handlerfactory.HandlerInterface {
			return &scimMe{
				s:         New(store),
				store:     store,
				domainURL: domainURL,
				userPath:  userPath(path),
				w:         w,
				r:         r,
			}
		},
	}
}

type scimMe struct {
	s         *Scim
	store     storage.Store
	domainURL string
	userPath  string
	w         http.ResponseWriter
	r         *http.Request
	user      *scimUser
}

// Setup initializes the handler
func (h *scimMe) Setup(tx storage.Tx) (int, error) {
	h.r.ParseForm()
	h.user = &scimUser{
		s:         h.s,
		store:     h.store,
		domainURL: h.domainURL,
		userPath:  userPath(h.userPath),
		w:         h.w,
		r:         h.r,
		input:     &spb.Patch{},
	}
	return h.user.Setup(tx)
}

// LookupItem returns true if the named object is found
func (h *scimMe) LookupItem(name string, vars map[string]string) bool {
	return h.user.LookupItem(h.user.auth.ID.Subject, vars)
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

// UserFactory creates SCIM /Users/<id> request handlers
func UserFactory(store storage.Store, domainURL, path string) *handlerfactory.HandlerFactory {
	return &handlerfactory.HandlerFactory{
		TypeName:            "user",
		PathPrefix:          path,
		HasNamedIdentifiers: true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) handlerfactory.HandlerInterface {
			return &scimUser{
				s:         New(store),
				store:     store,
				domainURL: domainURL,
				userPath:  userPath(path),
				w:         w,
				r:         r,
				input:     &spb.Patch{},
			}
		},
	}
}

type scimUser struct {
	s         *Scim
	store     storage.Store
	domainURL string
	userPath  string
	w         http.ResponseWriter
	r         *http.Request
	item      *cpb.Account
	input     *spb.Patch
	save      *cpb.Account
	auth      *auth.Context
	tx        storage.Tx
}

// Setup initializes the handler
func (h *scimUser) Setup(tx storage.Tx) (int, error) {
	auth, err := auth.FromContext(h.r.Context())
	if err != nil {
		return http.StatusUnauthorized, err
	}
	if h.r.Method == http.MethodPatch {
		if err := jsonpb.Unmarshal(h.r.Body, h.input); err != nil && err != io.EOF {
			return http.StatusBadRequest, err
		}
	}

	h.auth = auth
	h.tx = tx

	return http.StatusOK, nil
}

// LookupItem returns true if the named object is found
func (h *scimUser) LookupItem(name string, vars map[string]string) bool {
	realm := getRealm(h.r)
	acct := &cpb.Account{}
	acct, _, err := h.s.LoadAccount(name, realm, h.auth.IsAdmin, h.tx)
	if err != nil {
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

	if len(h.input.Schemas) != 1 || h.input.Schemas[0] != scimPatchSchema {
		return fmt.Errorf("PATCH requires schemas set to only be %q", scimPatchSchema)
	}

	return nil
}

// Get sends a GET method response
func (h *scimUser) Get(name string) error {
	httputil.WriteProtoResp(h.w, newScimUser(h.item, getRealm(h.r), h.domainURL, h.userPath))
	return nil
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
	h.save = &cpb.Account{}
	proto.Merge(h.save, h.item)
	for i, patch := range h.input.Operations {
		src := patchSource(patch.Value)
		var dst *string
		path := patch.Path
		// When updating a photo from the list, always update the photo in the primary profile.
		if photoPathRE.MatchString(path) {
			path = "photo"
		} else if emailPathRE.MatchString(path) {
			path = "emails"
		}
		switch path {
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
			dst = &h.save.Profile.FormattedName
			if patch.Op == "remove" || len(src) == 0 {
				return fmt.Errorf("operation %d: cannot set %q to an empty value", i, path)
			}

		case "name.familyName":
			dst = &h.save.Profile.FamilyName

		case "name.givenName":
			dst = &h.save.Profile.GivenName

		case "name.middleName":
			dst = &h.save.Profile.MiddleName

		case "displayName":
			dst = &h.save.Profile.Name
			if patch.Op == "remove" || len(src) == 0 {
				return fmt.Errorf("operation %d: cannot set %q to an empty value", i, path)
			}

		case "profileUrl":
			dst = &h.save.Profile.Profile

		case "locale":
			dst = &h.save.Profile.Locale
			if len(src) > 0 && !timeutil.IsLocale(src) {
				return fmt.Errorf("operation %d: %q is not a recognized locale", i, path)
			}

		case "timezone":
			dst = &h.save.Profile.ZoneInfo
			if len(src) > 0 && !timeutil.IsTimeZone(src) {
				return fmt.Errorf("operation %d: %q is not a recognized time zone", i, src)
			}

		case "emails":
			if patch.Op == "add" {
				// SCIM extension for linking accounts.
				if src != auth.LinkAuthorizationHeader {
					return fmt.Errorf("operation %d: %q must be set to %q", i, src, auth.LinkAuthorizationHeader)
				}
				if err := h.linkEmail(); err != nil {
					return err
				}
				break
			}
			// Standard SCIM email functionality.
			link, match, err := selectLink(patch.Path, emailPathRE, scimEmailFilterMap, h.save)
			if err != nil {
				return err
			}
			dst = nil // operation can be skipped by logic after this switch block (i.e. no destination to write)
			if link == nil {
				break
			}
			if len(match[2]) == 0 {
				// When match[2] is empty, the operation applies to the entire email object.
				if patch.Op != "remove" {
					return fmt.Errorf("operation %d: path %q only supported for remove", i, path)
				}
				if len(h.save.ConnectedAccounts) < 2 {
					return fmt.Errorf("operation %d: cannot unlink the only email address for a given account", i)
				}
				// Unlink account
				for idx, connect := range h.save.ConnectedAccounts {
					if connect.Properties.Subject == link.Properties.Subject {
						h.save.ConnectedAccounts = append(h.save.ConnectedAccounts[:idx], h.save.ConnectedAccounts[idx+1:]...)
						if err := h.s.RemoveAccountLookup(link.LinkRevision, getRealm(h.r), link.Properties.Subject, h.r, h.auth.ID, h.tx); err != nil {
							return fmt.Errorf("service dependencies not available; try again later")
						}
						break
					}
				}
			} else {
				// This logic is valid for all patch.Op operations.
				primary := strings.ToLower(src) == "true" && patch.Op != "remove"
				if primary {
					// Make all entries not primary, then set the primary below
					for _, entry := range h.save.ConnectedAccounts {
						entry.Primary = false
					}
				}
				link.Primary = primary
			}

		case "photo":
			dst = &h.save.Profile.Picture
			if !strutil.IsImageURL(src) {
				return fmt.Errorf("invalid photo URL %q", src)
			}

		default:
			return fmt.Errorf("operation %d: invalid path %q", i, path)
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
	httputil.WriteProtoResp(h.w, newScimUser(h.save, getRealm(h.r), h.domainURL, h.userPath))
	return nil
}

// Remove receives a DELETE method request
func (h *scimUser) Remove(name string) error {
	h.save = &cpb.Account{}
	proto.Merge(h.save, h.item)
	for _, link := range h.save.ConnectedAccounts {
		if link.Properties == nil || len(link.Properties.Subject) == 0 {
			continue
		}
		if err := h.s.RemoveAccountLookup(link.LinkRevision, getRealm(h.r), link.Properties.Subject, h.r, h.auth.ID, h.tx); err != nil {
			return fmt.Errorf("service dependencies not available; try again later")
		}
	}
	h.save.ConnectedAccounts = []*cpb.ConnectedAccount{}
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
	return h.s.SaveAccount(h.item, h.save, desc, h.r, h.auth.ID.Subject, h.tx)
}

func (h *scimUser) linkEmail() error {
	// This scope check is done here because it has only been determined now
	// that the standard user token needs it for the specific patch requested.
	if !strutil.ContainsWord(h.auth.ID.Scope, "link") {
		return fmt.Errorf("bearer token unauthorized for scope %q", "link")
	}
	// Linked token has been validated and scope "link" check has also been done.
	if h.auth.LinkedID == nil {
		return status.Errorf(codes.FailedPrecondition, "linked account bearer token header %q not provided", auth.LinkAuthorizationHeader)
	}
	linkSub := h.auth.LinkedID.Subject
	idSub := h.save.Properties.Subject
	if linkSub == idSub {
		return fmt.Errorf("the accounts provided are already linked together")
	}
	linkAcct, _, err := h.s.LoadAccount(linkSub, getRealm(h.r), false, h.tx)
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
		lookup := &cpb.AccountLookup{
			Subject:  h.save.Properties.Subject,
			Revision: acct.LinkRevision,
			State:    storage.StateActive,
		}
		if err := h.s.SaveAccountLookup(lookup, getRealm(h.r), acct.Properties.Subject, h.r, h.auth.ID, h.tx); err != nil {
			return fmt.Errorf("service dependencies not available; try again later")
		}
		acct.LinkRevision++
		h.save.ConnectedAccounts = append(h.save.ConnectedAccounts, acct)
	}
	linkAcct.ConnectedAccounts = make([]*cpb.ConnectedAccount, 0)
	linkAcct.State = "LINKED"
	linkAcct.Owner = h.save.Properties.Subject
	if err = h.s.SaveAccount(nil, linkAcct, "LINK account", h.r, h.auth.ID.Subject, h.tx); err != nil {
		return err
	}
	return nil
}

//////////////////////////////////////////////////////////////////

// UsersFactory creates SCIM Users request handlers.
func UsersFactory(store storage.Store, domainURL, path string) *handlerfactory.HandlerFactory {
	return &handlerfactory.HandlerFactory{
		TypeName:            "users",
		PathPrefix:          path,
		HasNamedIdentifiers: true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) handlerfactory.HandlerInterface {
			return &scimUsers{
				s:         New(store),
				store:     store,
				domainURL: domainURL,
				userPath:  userPath(path),
				w:         w,
				r:         r,
			}
		},
	}
}

type scimUsers struct {
	s         *Scim
	store     storage.Store
	domainURL string
	userPath  string
	w         http.ResponseWriter
	r         *http.Request
	id        *ga4gh.Identity
	tx        storage.Tx
}

// Setup initializes the handler
func (h *scimUsers) Setup(tx storage.Tx) (int, error) {
	a, err := auth.FromContext(h.r.Context())
	if err != nil {
		return http.StatusUnauthorized, err
	}
	h.id = a.ID
	h.tx = tx
	return http.StatusOK, nil
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
	filters, err := storage.BuildFilters(httputil.QueryParam(h.r, "filter"), scimUserFilterMap)
	if err != nil {
		return err
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
	count, err := h.store.MultiReadTx(storage.AccountDatatype, getRealm(h.r), storage.DefaultUser, filters, offset, max, m, &cpb.Account{}, h.tx)
	if err != nil {
		return err
	}
	accts := make(map[string]*cpb.Account)
	subjects := []string{}
	for _, u := range m {
		for _, v := range u {
			if acct, ok := v.(*cpb.Account); ok {
				accts[acct.Properties.Subject] = acct
				subjects = append(subjects, acct.Properties.Subject)
			}
		}
	}
	sort.Strings(subjects)
	realm := getRealm(h.r)
	var list []*spb.User
	for _, sub := range subjects {
		list = append(list, newScimUser(accts[sub], realm, h.domainURL, h.userPath))
	}

	if max < count {
		max = count
	}
	resp := &spb.ListUsersResponse{
		Schemas:      []string{scimListSchema},
		TotalResults: uint32(offset + count),
		ItemsPerPage: uint32(len(list)),
		StartIndex:   uint32(start),
		Resources:    list,
	}
	httputil.WriteProtoResp(h.w, resp)
	return nil
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

////////////////////////////////////////////////////////////

func newScimUser(acct *cpb.Account, realm, domainURL, abstractPath string) *spb.User {
	var emails []*spb.Attribute
	var photos []*spb.Attribute
	primaryPic := acct.GetProfile().GetPicture()
	if len(primaryPic) > 0 {
		photos = append(photos, &spb.Attribute{Value: strutil.ToURL(primaryPic, domainURL), Primary: true})
	}
	for _, ca := range acct.ConnectedAccounts {
		if len(ca.Properties.Email) > 0 {
			emails = append(emails, &spb.Attribute{
				Value:             ca.Properties.Email,
				ExtensionVerified: ca.Properties.EmailVerified,
				Primary:           ca.Primary,
				Ref:               emailRef(ca),
			})
		}
		if ca.Profile == nil {
			continue
		}
		if pic := ca.GetProfile().GetPicture(); len(pic) > 0 && pic != primaryPic {
			photos = append(photos, &spb.Attribute{Value: strutil.ToURL(pic, domainURL)})
		}
	}

	path := strings.ReplaceAll(abstractPath, "{realm}", realm)
	path = strings.ReplaceAll(path, "{name}", acct.Properties.Subject)

	return &spb.User{
		Schemas:    []string{scimUserSchema},
		Id:         acct.Properties.Subject,
		ExternalId: acct.Properties.Subject,
		Meta: &spb.ResourceMetadata{
			ResourceType: "User",
			Created:      timeutil.TimestampString(int64(acct.Properties.Created)),
			LastModified: timeutil.TimestampString(int64(acct.Properties.Modified)),
			Location:     domainURL + path,
			Version:      strconv.FormatInt(acct.Revision, 10),
		},
		Name: &spb.Name{
			Formatted:  formattedName(acct),
			FamilyName: acct.Profile.FamilyName,
			GivenName:  acct.Profile.GivenName,
			MiddleName: acct.Profile.MiddleName,
		},
		DisplayName:       acct.Profile.Name,
		ProfileUrl:        acct.Profile.Profile,
		PreferredLanguage: acct.Profile.Locale,
		Locale:            acct.Profile.Locale,
		Timezone:          acct.Profile.ZoneInfo,
		UserName:          acct.Properties.Subject,
		Emails:            emails,
		Photos:            photos,
		Active:            acct.State == storage.StateActive,
	}
}

func userPath(abstract string) string {
	path := strings.ReplaceAll(abstract, "/Me", "/Users")
	if strings.Contains(abstract, "{name}") {
		return path
	}
	return path + "/{name}"
}

func formattedName(acct *cpb.Account) string {
	profile := acct.GetProfile()
	name := profile.FormattedName
	if len(name) == 0 {
		name = strutil.JoinNonEmpty([]string{profile.GivenName, profile.MiddleName, profile.FamilyName}, " ")
	}
	if len(name) == 0 {
		name = profile.Name
	}
	return name
}

func selectLink(selector string, re *regexp.Regexp, filterMap map[string]func(p proto.Message) string, acct *cpb.Account) (*cpb.ConnectedAccount, []string, error) {
	match := re.FindStringSubmatch(selector)
	if match == nil {
		return nil, nil, nil
	}
	filter, err := storage.BuildFilters(match[1], filterMap)
	if err != nil {
		return nil, nil, err
	}
	for _, link := range acct.ConnectedAccounts {
		if storage.MatchProtoFilters(filter, link) {
			return link, match, nil
		}
	}
	return nil, match, nil
}

func emailRef(link *cpb.ConnectedAccount) string {
	return "email/" + link.Provider + "/" + link.Properties.Subject
}

func patchSource(value string) string {
	// TODO: handle more complex substructure and remove "object" field.
	return value
}
