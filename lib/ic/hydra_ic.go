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
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/pborman/uuid" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/apis/hydraapi" /* copybara-comment: hydraapi */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/auth" /* copybara-comment: auth */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/hydra" /* copybara-comment: hydra */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/ic/v1" /* copybara-comment: go_proto */
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

	res, err := s.hydraLogin(challenge, login)
	if err != nil {
		hydra.SendLoginReject(w, r, s.httpClient, s.hydraAdminURL, challenge, err)
	} else {
		res.writeResp(w, r)
	}
}

type htmlPageOrRedirectURL struct {
	page     string
	redirect string
}

func (h *htmlPageOrRedirectURL) writeResp(w http.ResponseWriter, r *http.Request) {
	if len(h.page) > 0 {
		httputils.WriteHTMLResp(w, h.page)
	} else {
		httputils.WriteRedirect(w, r, h.redirect)
	}
}

// hydraLogin returns htmlpage, redirect and status error
func (s *Service) hydraLogin(challenge string, login *hydraapi.LoginRequest) (*htmlPageOrRedirectURL, error) {
	u, err := url.Parse(login.RequestURL)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, err.Error())
	}

	realm := u.Query().Get("realm")
	if len(realm) == 0 {
		realm = storage.DefaultRealm
	}

	cfg, err := s.loadConfig(nil, realm)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "%v", err.Error())
	}

	scopes := login.RequestedScope
	if len(scopes) == 0 {
		scopes = defaultIdpScopes
	}

	// Return login page if no login hint.
	loginHint := u.Query().Get("login_hint")
	if !strings.Contains(loginHint, ":") {
		// Return Login page.
		query := fmt.Sprintf("?scope=%s&login_challenge=%s", url.QueryEscape(strings.Join(scopes, " ")), url.QueryEscape(challenge))
		page, err := s.renderLoginPage(cfg, map[string]string{"realm": realm}, query)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "%v", err.Error())
		}
		return &htmlPageOrRedirectURL{page: page}, nil
	}

	// Skip login page and select the given idp when if contains login hint.
	hint := strings.SplitN(loginHint, ":", 2)
	loginHintProvider := hint[0]
	loginHintAccount := hint[1]

	// Idp login
	in := loginIn{
		realm:     realm,
		scope:     scopes,
		loginHint: loginHintAccount,
		provider:  loginHintProvider,
		challenge: challenge,
	}
	redirect, err := s.login(in, cfg)
	return &htmlPageOrRedirectURL{redirect: redirect}, err
}

// HydraConsent handles consent request from hydra.
func (s *Service) HydraConsent(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	// Use consent_challenge fetch information from hydra.
	challenge, sts := hydra.ExtractConsentChallenge(r)
	if sts != nil {
		httputils.WriteError(w, sts.Err())
		return
	}

	consent, err := hydra.GetConsentRequest(s.httpClient, s.hydraAdminURL, challenge)
	if err != nil {
		httputils.WriteError(w, err)
		return
	}

	res, err := s.hydraConsent(r, challenge, consent)
	if err != nil {
		hydra.SendConsentReject(w, r, s.httpClient, s.hydraAdminURL, challenge, err)
	} else {
		res.writeResp(w, r)
	}
}

func (s *Service) hydraConsent(r *http.Request, challenge string, consent *hydraapi.ConsentRequest) (_ *htmlPageOrRedirectURL, ferr error) {
	stateID, sts := hydra.ExtractStateIDInConsent(consent)
	if sts != nil {
		return nil, sts.Err()
	}

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

	state := &cpb.LoginState{}
	err = s.store.ReadTx(storage.LoginStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, state, tx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}

	state.ConsentChallenge = challenge
	state.Scope = strings.Join(consent.RequestedScope, " ")
	state.Audience = append(consent.RequestedAudience, consent.Client.ClientID)
	state.ClientName = consent.Client.Name

	cfg, err := s.loadConfig(tx, state.Realm)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "%v", err)
	}

	if s.skipInformationReleasePage {
		redirect, err := s.hydraConsentSkipInformationReleasePage(r, stateID, state, cfg, tx)
		return &htmlPageOrRedirectURL{redirect: redirect}, err
	}
	return s.hydraConsentRememberConsentOrInformationReleasePage(r, consent, stateID, state, cfg, tx)
}

func (s *Service) hydraConsentSkipInformationReleasePage(r *http.Request, stateID string, state *cpb.LoginState, cfg *pb.IcConfig, tx storage.Tx) (string, error) {
	err := s.store.DeleteTx(storage.LoginStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, tx)
	if err != nil {
		return "", status.Errorf(codes.Internal, "skip information release page delete state failed: %v", err)
	}

	secrets, err := s.loadSecrets(tx)
	if err != nil {
		return "", status.Errorf(codes.Internal, "skip information release page loadSecrets() failed: %v", err)
	}

	acct, st, err := s.scim.LoadAccount(state.Subject, state.Realm, false, tx)
	if err != nil {
		return "", status.Errorf(httputils.RPCCode(st), "skip information release page LoadAccount() failed: %v", err)
	}

	id, err := s.accountToIdentity(r.Context(), acct, cfg, secrets)
	if err != nil {
		return "", status.Errorf(codes.Internal, "skip information release page accountToIdentity() failed: %v", err)
	}

	redirect, err := s.hydraAcceptConsent(id, state)
	if err != nil {
		return "", err
	}
	return redirect, nil
}

func (s *Service) hydraConsentRememberConsentOrInformationReleasePage(r *http.Request, consent *hydraapi.ConsentRequest, stateID string, state *cpb.LoginState, cfg *pb.IcConfig, tx storage.Tx) (*htmlPageOrRedirectURL, error) {
	clientName := consent.Client.Name
	if len(clientName) == 0 {
		clientName = consent.Client.ClientID
	}
	if len(clientName) == 0 {
		return nil, status.Errorf(codes.Unavailable, "consent.Client.Name empty")
	}

	sub := consent.Subject
	if len(sub) == 0 {
		return nil, status.Errorf(codes.Unavailable, "consent.Subject empty")
	}

	err := s.store.WriteTx(storage.LoginStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, state, nil, tx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	a, err := auth.FromContext(r.Context())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}

	acct, st, err := s.scim.LoadAccount(sub, state.Realm, a.IsAdmin, tx)
	if err != nil {
		return nil, status.Errorf(httputils.RPCCode(st), "%v", err)
	}

	secrets, err := s.loadSecrets(tx)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "%v", err)
	}

	id, err := s.accountToIdentity(r.Context(), acct, cfg, secrets)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}

	id.Scope = strings.Join(consent.RequestedScope, " ")

	rcp, err := findRememberedConsent(s.store, consent.RequestedScope, id.Subject, state.Realm, state.ClientName, tx)
	if err != nil {
		return nil, err
	}

	if rcp != nil {
		scoped, err := scopedIdentity(id, rcp, id.Scope, s.getIssuerString(), id.Subject, time.Now().Unix(), id.NotBefore, id.Expiry)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "accept info release scopedIdentity() failed: %v", err)
		}

		redirect, err := s.hydraAcceptConsent(scoped, state)
		if err != nil {
			return nil, err
		}
		return &htmlPageOrRedirectURL{redirect: redirect}, nil
	}

	page := s.informationReleasePage(id, stateID, clientName, id.Scope)
	return &htmlPageOrRedirectURL{page: page}, nil
}

func identityToHydraMap(id *ga4gh.Identity) (map[string]interface{}, error) {
	b, err := json.Marshal(id)
	if err != nil {
		return nil, err
	}

	m := map[string]interface{}{}
	err = json.Unmarshal(b, &m)
	if err != nil {
		return nil, err
	}

	// Remove all standard claims which already included in hydra.
	claims := []string{"sub", "iss", "iat", "nbf", "exp", "scope", "aud", "azp", "jti", "nonce"}
	for _, n := range claims {
		delete(m, n)
	}
	return m, err
}

func (s *Service) hydraAcceptConsent(id *ga4gh.Identity, state *cpb.LoginState) (string, error) {
	m, err := identityToHydraMap(id)
	if err != nil {
		return "", status.Errorf(codes.Internal, "hydraAcceptConsent identityToHydraMap() failed: %v", err)
	}

	tokenID := uuid.New()
	m["tid"] = tokenID

	req := &hydraapi.HandledConsentRequest{
		GrantedAudience: state.Audience,
		GrantedScope:    strings.Split(state.Scope, " "),
		Session: &hydraapi.ConsentRequestSessionData{
			IDToken: m,
			AccessToken: map[string]interface{}{
				"tid": tokenID,
			},
		},
	}

	if len(id.Identities) != 0 {
		var identities []string
		for k := range id.Identities {
			identities = append(identities, k)
		}

		req.Session.AccessToken["identities"] = identities
	}

	resp, err := hydra.AcceptConsent(s.httpClient, s.hydraAdminURL, state.ConsentChallenge, req)
	if err != nil {
		return "", err
	}

	return resp.RedirectTo, nil
}
