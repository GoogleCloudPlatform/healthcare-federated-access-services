// Copyright 2020 Google LLC.
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
	"encoding/base64"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/golang/protobuf/jsonpb" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
	"bitbucket.org/creachadair/stringset" /* copybara-comment */
	"github.com/pborman/uuid" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/consentsapi" /* copybara-comment: consentsapi */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/errutil" /* copybara-comment: errutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/hydra" /* copybara-comment: hydra */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/timeutil" /* copybara-comment: timeutil */

	glog "github.com/golang/glog" /* copybara-comment */
	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	cspb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/store/consents" /* copybara-comment: go_proto */
)

const (
	rememberedConsentExpires = 90 * 24 * time.Hour
	maxRememberedConsent     = 200
)

func (s *Service) informationReleasePage(id *ga4gh.Identity, stateID, clientName, scope string) string {
	args := toInformationReleasePageArgs(id, stateID, clientName, scope)
	sb := &strings.Builder{}
	s.infomationReleasePageTmpl.Execute(sb, args)

	return sb.String()
}

func toInformationReleasePageArgs(id *ga4gh.Identity, stateID, clientName, scope string) *informationReleasePageArgs {
	args := &informationReleasePageArgs{
		ID:              id.Subject,
		ApplicationName: clientName,
		Scope:           scope,
		AssetDir:        assetPath,
		Information:     map[string][]*informationItem{},
		State:           stateID,
	}

	for _, s := range strings.Split(scope, " ") {
		switch {
		case s == "openid":
			continue

		case s == "offline":
			args.Offline = true

		case s == "profile":
			if len(id.Name) != 0 {
				args.Information["Profile"] = append(args.Information["Profile"], &informationItem{
					ID:    "profile.name",
					Title: "Name",
					Value: id.Name,
				})
			}
			if len(id.Email) != 0 {
				args.Information["Profile"] = append(args.Information["Profile"], &informationItem{
					ID:    "profile.email",
					Title: "Email",
					Value: id.Email,
				})
			}
			if len(id.Picture) > 0 || len(id.Locale) > 0 {
				args.Information["Profile"] = append(args.Information["Profile"], &informationItem{
					ID:    "profile.others",
					Title: "Others",
					Value: "Picture,Locale",
				})
			}

		case s == passportScope || s == ga4ghScope:
			for _, v := range id.VisaJWTs {
				info, err := visaToInformationItem(v)
				if err != nil {
					glog.Errorf("convert visa to info failed: %v", err)
					continue
				}

				args.Information["Visas"] = append(args.Information["Visas"], info)
			}

		case s == "account_admin":
			args.Information["Permission"] = append(args.Information["Permission"], &informationItem{
				ID:    "account_admin",
				Title: "account_admin",
				Value: "manage (modify) this account",
			})

		case s == "link":
			args.Information["Permission"] = append(args.Information["Permission"], &informationItem{
				ID:    "link",
				Title: "link",
				Value: "link this account to other accounts",
			})

		case s == "identities":
			if len(id.Identities) == 0 {
				continue
			}
			var ids []string
			for k := range id.Identities {
				ids = append(ids, k)
			}
			args.Information["Profile"] = append(args.Information["Profile"], &informationItem{
				ID:    "identities",
				Title: "Identities",
				Value: strings.Join(ids, ","),
			})

		default:
			// Should not reach here, scope has been validated on Hydra.
			glog.Errorf("Unknown scope: %s", s)
		}
	}

	return args
}

func visaToInformationItem(s string) (*informationItem, error) {
	v, err := ga4gh.NewVisaFromJWT(ga4gh.VisaJWT(s))
	if err != nil {
		return nil, err
	}

	marshaler := jsonpb.Marshaler{}
	ss, err := marshaler.MarshalToString(visaToConsentVisa(v))
	if err != nil {
		return nil, err
	}

	id := base64.StdEncoding.EncodeToString([]byte(ss))

	return &informationItem{
		ID:    id,
		Title: string(v.Data().Assertion.Type) + "@" + string(v.Data().Assertion.Source),
		Value: string(v.Data().Assertion.Value),
	}, nil
}

func visaToConsentVisa(v *ga4gh.Visa) *cspb.RememberedConsentPreference_Visa {
	return &cspb.RememberedConsentPreference_Visa{
		Type:   string(v.Data().Assertion.Type),
		Source: string(v.Data().Assertion.Source),
		By:     string(v.Data().Assertion.By),
		Iss:    v.Data().Issuer,
	}
}

type informationItem struct {
	Title string
	Value string
	ID    string
}

type informationReleasePageArgs struct {
	ApplicationName string
	Scope           string
	AssetDir        string
	ID              string
	Offline         bool
	Information     map[string][]*informationItem
	State           string
}

// normalizeRememberedConsentPreference change ANYTHING_NEEDED to release item.
func normalizeRememberedConsentPreference(rcp *cspb.RememberedConsentPreference) {
	if rcp.ReleaseType != cspb.RememberedConsentPreference_ANYTHING_NEEDED {
		return
	}

	rcp.ReleaseProfileName = true
	rcp.ReleaseProfileEmail = true
	rcp.ReleaseProfileOther = true
	rcp.ReleaseAccountAdmin = true
	rcp.ReleaseLink = true
	rcp.ReleaseIdentities = true
}

func scopedIdentity(identity *ga4gh.Identity, rcp *cspb.RememberedConsentPreference, scope, iss, subject string, iat, nbf, exp int64) (*ga4gh.Identity, error) {
	normalizeRememberedConsentPreference(rcp)
	var scopes []string
	for _, s := range strings.Split(scope, " ") {
		switch s {
		case "link":
			if !rcp.ReleaseLink {
				continue
			}
		case "account_admin":
			if !rcp.ReleaseAccountAdmin {
				continue
			}
		}
		scopes = append(scopes, s)
	}

	claims := &ga4gh.Identity{
		Issuer:           iss,
		Subject:          subject,
		IssuedAt:         iat,
		NotBefore:        nbf,
		ID:               uuid.New(),
		Expiry:           exp,
		Scope:            strings.Join(scopes, " "),
		IdentityProvider: identity.IdentityProvider,
	}
	// TODO: remove this extra "ga4gh" check once DDAP is compatible.
	if hasScopes("identities", scope, matchFullScope) || hasScopes(passportScope, scope, matchFullScope) || hasScopes(ga4ghScope, scope, matchFullScope) {
		if rcp.ReleaseIdentities {
			claims.Identities = identity.Identities
		}
	}
	if hasScopes("profile", scope, matchFullScope) {
		if rcp.ReleaseProfileName {
			claims.Name = identity.Name
			claims.FamilyName = identity.FamilyName
			claims.GivenName = identity.GivenName
			claims.Username = identity.Username
		}
		if rcp.ReleaseProfileEmail {
			claims.Email = identity.Email
		}
		if rcp.ReleaseProfileOther {
			claims.Picture = identity.Picture
			claims.Locale = identity.Locale
		}
	}
	if hasScopes("ga4gh_passport_v1", scope, matchFullScope) {
		if rcp.ReleaseType == cspb.RememberedConsentPreference_ANYTHING_NEEDED {
			claims.VisaJWTs = identity.VisaJWTs
		} else {
			visas, err := releasedVisas(identity.VisaJWTs, rcp.SelectedVisas)
			if err != nil {
				return nil, err
			}
			claims.VisaJWTs = visas
		}
	}

	return claims, nil
}

// releasedVisas finds all released visa.
func releasedVisas(visas []string, rVisas []*cspb.RememberedConsentPreference_Visa) ([]string, error) {
	var res []string
	for _, visa := range visas {
		match, err := matchVisa(visa, rVisas)
		if err != nil {
			return nil, err
		}
		if match {
			res = append(res, visa)
		}
	}

	return res, nil
}

// matchVisa checks if the given visa is in the released list.
func matchVisa(visaStr string, rVisas []*cspb.RememberedConsentPreference_Visa) (bool, error) {
	v, err := ga4gh.NewVisaFromJWT(ga4gh.VisaJWT(visaStr))
	if err != nil {
		return false, err
	}

	visa := visaToConsentVisa(v)
	for _, rv := range rVisas {
		if visa.Type != rv.Type {
			continue
		}
		if visa.Source != rv.Source {
			continue
		}
		if visa.By != rv.By {
			continue
		}
		if visa.Iss != rv.Iss {
			continue
		}
		return true, nil
	}

	return false, nil
}

// AcceptInformationRelease is the HTTP handler for ".../inforelease/accept" endpoint.
func (s *Service) AcceptInformationRelease(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	challenge, redirect, err := s.acceptInformationRelease(r)
	if err == nil {
		httputils.WriteRedirect(w, r, redirect)
		return
	}

	if s.useHydra && len(challenge) > 0 {
		hydra.SendConsentReject(w, r, s.httpClient, s.hydraAdminURL, challenge, err)
	} else {
		httputils.WriteError(w, err)
	}
}

// checkboxIDToConsentVisa convert ConsentVisa from base64 json string.
func checkboxIDToConsentVisa(s string) (*cspb.RememberedConsentPreference_Visa, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64 decoding remembered consent preference failed: %v", err)
	}

	visa := &cspb.RememberedConsentPreference_Visa{}
	if err := jsonpb.UnmarshalString(string(b), visa); err != nil {
		return nil, fmt.Errorf("json decoding remembered consent preference failed: %v", err)
	}

	return visa, nil
}

// toRememberedConsentPreference reads RememberedConsentPreference from request.
func toRememberedConsentPreference(r *http.Request) (*cspb.RememberedConsentPreference, error) {
	now := time.Now()
	rcp := &cspb.RememberedConsentPreference{
		RequestMatchType: cspb.RememberedConsentPreference_NONE,
		ReleaseType:      cspb.RememberedConsentPreference_SELECTED,
		CreateTime:       timeutil.TimestampProto(now),
		ExpireTime:       timeutil.TimestampProto(now.Add(rememberedConsentExpires)),
	}
	for k, v := range r.PostForm {
		switch k {
		case "state":
			continue
		case "profile.name":
			rcp.ReleaseProfileName = true
		case "profile.email":
			rcp.ReleaseProfileEmail = true
		case "profile.others":
			rcp.ReleaseProfileOther = true
		case "account_admin":
			rcp.ReleaseAccountAdmin = true
		case "link":
			rcp.ReleaseLink = true
		case "identities":
			rcp.ReleaseIdentities = true
		case "select-anything":
			rcp.ReleaseType = cspb.RememberedConsentPreference_ANYTHING_NEEDED
		case "remember":
			if len(v) == 0 {
				return nil, fmt.Errorf("remember format invalid")
			}
			switch v[0] {
			case "remember-samesubset":
				rcp.RequestMatchType = cspb.RememberedConsentPreference_SUBSET
			case "remember-any":
				rcp.RequestMatchType = cspb.RememberedConsentPreference_ANYTHING
			case "remember-none":
				rcp.RequestMatchType = cspb.RememberedConsentPreference_NONE
			default:
				return nil, fmt.Errorf("remember value invalid: %v", v[0])

			}
		default:
			visa, err := checkboxIDToConsentVisa(k)
			if err != nil {
				return nil, err
			}
			rcp.SelectedVisas = append(rcp.SelectedVisas, visa)
		}
	}

	return rcp, nil
}

// acceptInformationRelease returns challenge, redirect and status error
func (s *Service) acceptInformationRelease(r *http.Request) (_, _ string, ferr error) {
	stateID := httputils.QueryParam(r, "state")
	if len(stateID) == 0 {
		return "", "", status.Errorf(codes.InvalidArgument, "missing %q parameter", "state")
	}

	rcp, err := toRememberedConsentPreference(r)
	if err != nil {
		return "", "", status.Errorf(codes.InvalidArgument, "accept info release read consent failed: %v", err)
	}

	tx, err := s.store.Tx(true)
	if err != nil {
		return "", "", status.Errorf(codes.Unavailable, "accept info release transaction creation failed: %v", err)
	}
	defer func() {
		err := tx.Finish()
		if ferr == nil && err != nil {
			ferr = status.Errorf(codes.Internal, "accept info release transaction finish failed: %v", err)
		}
	}()

	state := &cpb.LoginState{}
	err = s.store.ReadTx(storage.LoginStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, state, tx)
	if err != nil {
		return "", "", status.Errorf(codes.Internal, "accept info release datastore read failed: %v", err)
	}

	// The temporary state for information releasing process can be only used once.
	err = s.store.DeleteTx(storage.LoginStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, tx)
	if err != nil {
		return "", "", status.Errorf(codes.Internal, "accept info release datastore delete failed: %v", err)
	}

	challenge := state.ConsentChallenge

	rcp.ClientName = state.ClientName
	// Save RememberedConsent if user select remember it.
	if rcp.RequestMatchType != cspb.RememberedConsentPreference_NONE {
		if err := s.cleanupRememberedConsent(state.Subject, state.Realm, tx); err != nil {
			return challenge, "", err
		}

		rID := uuid.New()
		rcp.RequestedScopes = strings.Split(state.Scope, " ")
		err = s.store.WriteTx(storage.RememberedConsentDatatype, state.Realm, state.Subject, rID, storage.LatestRev, rcp, nil, tx)
		if err != nil {
			return challenge, "", status.Errorf(codes.Internal, "accept info release datastore write remember consent failed: %v", err)
		}
	}

	cfg, err := s.loadConfig(tx, state.Realm)
	if err != nil {
		return challenge, "", status.Errorf(codes.Internal, "accept info release loadConfig() failed: %v", err)
	}

	secrets, err := s.loadSecrets(tx)
	if err != nil {
		return challenge, "", status.Errorf(codes.Internal, "accept info release loadSecrets() failed: %v", err)
	}

	acct, st, err := s.scim.LoadAccount(state.Subject, state.Realm, false, tx)
	if err != nil {
		return challenge, "", status.Errorf(httputils.RPCCode(st), "accept info release LoadAccount() failed: %v", err)
	}

	id, err := s.accountToIdentity(r.Context(), acct, cfg, secrets)
	if err != nil {
		return challenge, "", status.Errorf(codes.Internal, "accept info release accountToIdentity() failed: %v", err)
	}

	now := time.Now().Unix()

	scoped, err := scopedIdentity(id, rcp, state.Scope, s.getIssuerString(), state.Subject, now, id.NotBefore, id.Expiry)
	if err != nil {
		return challenge, "", status.Errorf(codes.Internal, "accept info release scopedIdentity() failed: %v", err)
	}

	if s.useHydra {
		addr, err := s.hydraAcceptConsent(scoped, state)
		if err != nil {
			return challenge, "", status.Errorf(codes.Internal, "accept info release hydraAcceptConsent() failed: %v", err)
		}
		return challenge, addr, nil
	}

	return challenge, "", status.Errorf(codes.Unimplemented, "oidc service not supported")
}

// cleanupRememberedConsent delete expired RememberedConsent or oldest RememberedConsent if count of RememberedConsent over maxRememberedConsent
func (s *Service) cleanupRememberedConsent(user, realm string, tx storage.Tx) error {
	rcs, err := findRememberedConsentsByUser(s.store, user, realm, "", 0, maxRememberedConsent+10, tx)
	if err != nil {
		return status.Errorf(codes.Unavailable, "cleanupRememberedConsent %v", err)
	}

	var list []*rememberedConsentPreferenceWithID
	for k, v := range rcs {
		list = append(list, &rememberedConsentPreferenceWithID{id: k, rcp: v})
	}

	// order by expire time.
	sort.Slice(list, func(i int, j int) bool {
		return list[i].rcp.ExpireTime.Seconds < list[j].rcp.ExpireTime.Seconds
	})

	i := 0

	// delete item over limit not matter if it still valid.
	for ; len(list)-i >= maxRememberedConsent; i++ {
		if err := s.store.DeleteTx(storage.RememberedConsentDatatype, realm, user, list[i].id, storage.LatestRev, tx); err != nil {
			return status.Errorf(codes.Unavailable, "cleanupRememberedConsent delete item over limit failed: %v", err)
		}
	}

	now := time.Now().Unix()

	// delete expired item.
	for ; i < len(list); i++ {
		if list[i].rcp.ExpireTime.Seconds > now {
			break
		}
		if err := s.store.DeleteTx(storage.RememberedConsentDatatype, realm, user, list[i].id, storage.LatestRev, tx); err != nil {
			return status.Errorf(codes.Unavailable, "cleanupRememberedConsent delete expired item failed: %v", err)
		}
	}

	return nil
}

type rememberedConsentPreferenceWithID struct {
	rcp *cspb.RememberedConsentPreference
	id  string
}

// RejectInformationRelease is the HTTP handler for ".../inforelease/reject" endpoint.
func (s *Service) RejectInformationRelease(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	challenge, err := s.rejectInformationRelease(r)

	if err == nil {
		glog.Errorln("rejectInformationRelease() should return err")
		err = status.Errorf(codes.Internal, "unknown err from rejectInformationRelease()")
	}

	if s.useHydra && len(challenge) > 0 {
		hydra.SendConsentReject(w, r, s.httpClient, s.hydraAdminURL, challenge, err)
	} else {
		httputils.WriteError(w, err)
	}
}

// rejectInformationRelease returns challenge and status error
func (s *Service) rejectInformationRelease(r *http.Request) (_ string, ferr error) {
	stateID := httputils.QueryParam(r, "state")
	if len(stateID) == 0 {
		return "", status.Errorf(codes.InvalidArgument, "missing %q parameter", "state")
	}

	tx, err := s.store.Tx(true)
	if err != nil {
		return "", status.Errorf(codes.Unavailable, "reject info release transaction creation failed: %v", err)
	}
	defer func() {
		err := tx.Finish()
		if ferr == nil && err != nil {
			ferr = status.Errorf(codes.Internal, "reject info release transaction finish failed: %v", err)
		}
	}()

	state := &cpb.LoginState{}
	err = s.store.ReadTx(storage.LoginStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, state, tx)
	if err != nil {
		return "", status.Errorf(codes.Internal, "reject info release datastore read failed: %v", err)
	}

	// The temporary state for information releasing process can be only used once.
	err = s.store.DeleteTx(storage.LoginStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, tx)
	if err != nil {
		return "", status.Errorf(codes.Internal, "reject info release datastore delete failed: %v", err)
	}

	challenge := state.ConsentChallenge
	return challenge, errutil.WithErrorReason("user_denied", status.Errorf(codes.Unauthenticated, "User denied releasing consent"))
}

// findRememberedConsent for user and consent request.
// will match the remembered consent and incoming request in order:
// 1. match type = anything remembered consent
// 2. remembered consent has exact the same scope with request
// 3. request scope is subset of remembered consent scope
func findRememberedConsent(store storage.Store, requestedScope []string, subject, realm, clientName string, tx storage.Tx) (*cspb.RememberedConsentPreference, error) {
	rcps, err := findRememberedConsentsByUser(store, subject, realm, clientName, 0, maxRememberedConsent, tx)
	if err != nil {
		return nil, err
	}

	var matchSame *cspb.RememberedConsentPreference
	var matchSubset *cspb.RememberedConsentPreference

	reqScope := scopesToStringSet(requestedScope)
	for _, rcp := range rcps {
		if rcp.RequestMatchType == cspb.RememberedConsentPreference_ANYTHING {
			return rcp, nil
		}

		sco := scopesToStringSet(rcp.RequestedScopes)
		// do not early return here to keep stable order: ANYTHING, SAME, SUBSET
		if sco.Equals(reqScope) {
			matchSame = rcp
		}

		if sco.IsSubset(reqScope) {
			matchSubset = rcp
		}
	}

	if matchSame != nil {
		return matchSame, nil
	}

	return matchSubset, nil
}

func scopesToStringSet(scopes []string) stringset.Set {
	set := stringset.Set{}
	for _, s := range scopes {
		set.Add(s)
	}

	return set
}

// findRememberedConsentsByUser returns all RememberedConsents of user of client.
func findRememberedConsentsByUser(store storage.Store, subject, realm, clientName string, offset, pageSize int, tx storage.Tx) (map[string]*cspb.RememberedConsentPreference, error) {
	content := make(map[string]map[string]proto.Message)
	count, err := store.MultiReadTx(storage.RememberedConsentDatatype, realm, subject, nil, offset, pageSize, content, &cspb.RememberedConsentPreference{}, tx)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "findRememberedConsentsByUser MultiReadTx() failed: %v", err)
	}

	res := map[string]*cspb.RememberedConsentPreference{}
	if count == 0 {
		return res, nil
	}

	now := time.Now().Unix()
	for k, v := range content[subject] {
		rcp, ok := v.(*cspb.RememberedConsentPreference)
		if !ok {
			return nil, status.Errorf(codes.Internal, "findRememberedConsentsByUser obj type incorrect: user=%s, id=%s", subject, k)
		}
		// remove expired items
		if rcp.ExpireTime.Seconds < now {
			continue
		}
		// filter for clientName
		if len(clientName) > 0 && rcp.ClientName != clientName {
			continue
		}

		res[k] = rcp
	}

	return res, nil
}

// clients fetchs oauth clients
func (s *Service) clients(tx storage.Tx) (map[string]*cpb.Client, error) {
	cfg, err := s.loadConfig(tx, storage.DefaultRealm)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "load clients failed: %v", err)
	}

	return cfg.Clients, nil
}

func (s *Service) consentService() *consentsapi.Service {
	return &consentsapi.Service{
		Store:                        s.store,
		FindRememberedConsentsByUser: findRememberedConsentsByUser,
		Clients:                      s.clients,
	}
}
