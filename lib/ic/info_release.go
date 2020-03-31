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
	"net/http"
	"strings"

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/golang/protobuf/jsonpb" /* copybara-comment */
	"github.com/pborman/uuid" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/errutil" /* copybara-comment: errutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/hydra" /* copybara-comment: hydra */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	glog "github.com/golang/glog" /* copybara-comment */
	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	cspb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/store/consents" /* copybara-comment: go_proto */
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

func scopedIdentity(identity *ga4gh.Identity, scope, iss, subject, nonce string, iat, nbf, exp int64, aud []string, azp string) *ga4gh.Identity {
	claims := &ga4gh.Identity{
		Issuer:           iss,
		Subject:          subject,
		Audiences:        ga4gh.Audiences(aud),
		IssuedAt:         iat,
		NotBefore:        nbf,
		ID:               uuid.New(),
		AuthorizedParty:  azp,
		Expiry:           exp,
		Scope:            scope,
		IdentityProvider: identity.IdentityProvider,
		Nonce:            nonce,
	}
	if !hasScopes("refresh", scope, matchFullScope) {
		// TODO: remove this extra "ga4gh" check once DDAP is compatible.
		if hasScopes("identities", scope, matchFullScope) || hasScopes(passportScope, scope, matchFullScope) || hasScopes(ga4ghScope, scope, matchFullScope) {
			claims.Identities = identity.Identities
		}
		if hasScopes("profile", scope, matchFullScope) {
			claims.Name = identity.Name
			claims.FamilyName = identity.FamilyName
			claims.GivenName = identity.GivenName
			claims.Username = identity.Username
			claims.Picture = identity.Picture
			claims.Locale = identity.Locale
			claims.Email = identity.Email
			claims.Picture = identity.Picture
		}
		if hasScopes("ga4gh_passport_v1", scope, matchFullScope) {
			claims.VisaJWTs = identity.VisaJWTs
		}
	}

	return claims
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

// acceptInformationRelease returns challenge, redirect and status error
func (s *Service) acceptInformationRelease(r *http.Request) (_, _ string, ferr error) {
	stateID := httputils.QueryParam(r, "state")
	if len(stateID) == 0 {
		return "", "", status.Errorf(codes.InvalidArgument, "missing %q parameter", "state")
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

	cfg, err := s.loadConfig(tx, state.Realm)
	if err != nil {
		return challenge, "", status.Errorf(codes.Internal, "accept info release loadConfig() failed: %v", err)
	}

	if s.useHydra {
		addr, err := s.hydraAcceptConsent(r, state, cfg, tx)
		if err != nil {
			return challenge, "", status.Errorf(codes.Internal, "accept info release hydraAcceptConsent() failed: %v", err)
		}
		return challenge, addr, nil
	}

	return challenge, "", status.Errorf(codes.Unimplemented, "oidc service not supported")
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
