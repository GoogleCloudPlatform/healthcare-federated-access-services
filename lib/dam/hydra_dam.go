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
	"net/http"
	"net/url"

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"golang.org/x/oauth2" /* copybara-comment */
	"bitbucket.org/creachadair/stringset" /* copybara-comment */
	"github.com/pborman/uuid" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/apis/hydraapi" /* copybara-comment: hydraapi */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/errutil" /* copybara-comment: errutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/hydra" /* copybara-comment: hydra */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
)

const (
	stateIDInHydra = "state"
)

// HydraLogin handles login request from hydra.
func (s *Service) HydraLogin(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	// Use login_challenge fetch information from hydra.
	challenge, sts := hydra.ExtractLoginChallenge(r)
	if sts != nil {
		httputils.WriteError(w, sts.Err())
		return
	}

	login, err := hydra.GetLoginRequest(s.httpClient, s.hydraAdminURL, challenge)
	if err != nil {
		httputils.WriteError(w, err)
		return
	}

	redirect, err := s.hydraLogin(r.Context(), challenge, login)
	if err != nil {
		hydra.SendLoginReject(w, r, s.httpClient, s.hydraAdminURL, challenge, err)
	} else {
		httputils.WriteRedirect(w, r, redirect)
	}
}

// hydraLogin returns redirect and status error
func (s *Service) hydraLogin(ctx context.Context, challenge string, login *hydraapi.LoginRequest) (string, error) {
	u, err := url.Parse(login.RequestURL)
	if err != nil {
		return "", errutil.WithErrorReason("url_parse", status.Errorf(codes.FailedPrecondition, "url parse: %v", err))
	}

	in := authHandlerIn{
		challenge:         challenge,
		requestedAudience: append(login.RequestedAudience, login.Client.ClientID),
		requestedScope:    login.RequestedScope,
		clientID:          login.Client.ClientID,
		clientName:        login.Client.Name,
	}

	// Request tokens for call DAM endpoints, if scope includes "identities".
	if stringset.Contains(login.RequestedScope, "identities") {
		in.tokenType = pb.ResourceTokenRequestState_ENDPOINT
		in.realm = u.Query().Get("realm")
		if len(in.realm) == 0 {
			in.realm = storage.DefaultRealm
		}
	} else {
		in.tokenType = pb.ResourceTokenRequestState_DATASET
		in.ttl, err = extractTTL(u.Query().Get("max_age"), u.Query().Get("ttl"))
		if err != nil {
			return "", errutil.WithErrorReason("ttl_invalid", status.Errorf(codes.InvalidArgument, "ttl invalid: %v", err))
		}

		list := u.Query()["resource"]
		in.resources, err = s.resourceViewRoleFromRequest(list)
		if err != nil {
			return "", errutil.WithErrorReason("resource_invalid", status.Errorf(codes.InvalidArgument, "resource invalid: %v", err))
		}

		in.responseKeyFile = u.Query().Get("response_type") == "key-file-type"
	}

	out, err := s.auth(ctx, in)
	if err != nil {
		return "", err
	}

	var opts []oauth2.AuthCodeOption
	loginHint := u.Query().Get("login_hint")
	if len(loginHint) != 0 {
		opt := oauth2.SetAuthURLParam("login_hint", loginHint)
		opts = append(opts, opt)
	}

	auth := out.oauth.AuthCodeURL(out.stateID, opts...)

	return auth, nil
}

// HydraConsent handles consent request from hydra.
func (s *Service) HydraConsent(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	// Use consent_challenge fetch information from hydra.
	challenge, st := hydra.ExtractConsentChallenge(r)
	if st != nil {
		httputils.WriteError(w, st.Err())
		return
	}

	consent, err := hydra.GetConsentRequest(s.httpClient, s.hydraAdminURL, challenge)
	if err != nil {
		httputils.WriteError(w, err)
		return
	}

	pageOrRedirect, err := s.hydraConsent(challenge, consent)
	if err != nil {
		hydra.SendConsentReject(w, r, s.httpClient, s.hydraAdminURL, challenge, err)
	} else {
		pageOrRedirect.writeResp(w, r)
	}
}

// hydraConsent returns redirect and status error
func (s *Service) hydraConsent(challenge string, consent *hydraapi.ConsentRequest) (_ *htmlPageOrRedirectURL, ferr error) {
	tx, err := s.store.Tx(true)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "%v", err)
	}
	defer func() {
		err := tx.Finish()
		if ferr == nil && err != nil {
			ferr = status.Errorf(codes.Internal, "%v", err)
		}
	}()
	var stateID string
	stateID, sts := hydra.ExtractStateIDInConsent(consent)
	if sts != nil {
		return nil, sts.Err()
	}

	if len(stateID) == 0 {
		return nil, status.Errorf(codes.FailedPrecondition, "token format invalid: stateID not found")
	}

	state := &pb.ResourceTokenRequestState{}
	err = s.store.ReadTx(storage.ResourceTokenRequestStateDataType, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, state, tx)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read state failed: %v", err)
	}

	state.ConsentChallenge = challenge
	err = s.store.WriteTx(storage.ResourceTokenRequestStateDataType, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, state, nil, tx)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, err.Error())
	}

	if s.skipInformationReleasePage {
		return s.hydraConsentSkipInformationReleasePage(consent, stateID, state, tx)
	}
	return s.hydraConsentRememberConsentOrInformationReleasePage(consent, stateID, state, tx)
}

func (s *Service) hydraConsentSkipInformationReleasePage(consent *hydraapi.ConsentRequest, stateID string, state *pb.ResourceTokenRequestState, tx storage.Tx) (*htmlPageOrRedirectURL, error) {
	return s.acceptHydraConsent(stateID, state, tx)
}

func (s *Service) acceptHydraConsent(stateID string, state *pb.ResourceTokenRequestState, tx storage.Tx) (*htmlPageOrRedirectURL, error) {
	tokenID := uuid.New()

	req := &hydraapi.HandledConsentRequest{
		GrantedAudience: state.RequestedAudience,
		GrantedScope:    state.RequestedScope,
		Session: &hydraapi.ConsentRequestSessionData{
			AccessToken: map[string]interface{}{
				"tid": tokenID,
			},
			IDToken: map[string]interface{}{
				"tid": tokenID,
			},
		},
	}

	if state.Type == pb.ResourceTokenRequestState_ENDPOINT {
		req.Session.AccessToken["identities"] = state.Identities
		// For endpoint tokens, state is not needed any more. For dataset tokens, state is still needed for exchanging resource token.
		err := s.store.DeleteTx(storage.ResourceTokenRequestStateDataType, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, tx)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "delete state failed: %v", err)
		}
	} else {
		req.Session.AccessToken["cart"] = stateID
	}

	resp, err := hydra.AcceptConsent(s.httpClient, s.hydraAdminURL, state.ConsentChallenge, req)
	if err != nil {
		return nil, err
	}

	return &htmlPageOrRedirectURL{redirect: resp.RedirectTo}, nil
}

func (s *Service) extractCartFromAccessToken(id *ga4gh.Identity) (string, error) {
	v, ok := id.Extra["cart"]
	if !ok {
		return "", status.Errorf(codes.Unauthenticated, "token does not have 'cart' claim")
	}

	cart, ok := v.(string)
	if !ok {
		return "", status.Errorf(codes.Internal, "token 'cart' claim have unwanted type")
	}

	if len(cart) == 0 {
		return "", status.Errorf(codes.Unauthenticated, "token has empty 'cart' claim")
	}

	return cart, nil
}

type htmlPageOrRedirectURL struct {
	page     string
	redirect string
}

func (h *htmlPageOrRedirectURL) writeResp(w http.ResponseWriter, r *http.Request) {
	if len(h.page) > 0 {
		httputils.WriteHTMLResp(w, h.page, nil)
	} else {
		httputils.WriteRedirect(w, r, h.redirect)
	}
}

