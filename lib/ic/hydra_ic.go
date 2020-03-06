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
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
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
	tpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/store/tokens" /* copybara-comment: go_proto */
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
		httputils.WriteError(w, status.Errorf(codes.Unavailable, "%v", err))
		return
	}

	if hydra.LoginSkip(w, r, s.httpClient, login, s.hydraAdminURL, challenge) {
		return
	}

	u, err := url.Parse(login.RequestURL)
	if err != nil {
		httputils.WriteError(w, status.Errorf(codes.Unavailable, "%v", err))
		return
	}

	realm := u.Query().Get("realm")
	if len(realm) == 0 {
		realm = storage.DefaultRealm
	}

	cfg, err := s.loadConfig(nil, realm)
	if err != nil {
		httputils.WriteError(w, status.Errorf(codes.Unavailable, "%v", err))
		return
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
			httputils.WriteError(w, status.Errorf(codes.Unavailable, "%v", err))
			return
		}
		httputils.WriteHTMLResp(w, page)
		return
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
		idpName:   loginHintProvider,
		challenge: challenge,
	}
	s.login(in, w, r, cfg)
}

func (s *Service) hydraLoginError(w http.ResponseWriter, r *http.Request, state, errName, errDesc string) {
	var loginState cpb.LoginState
	err := s.store.Read(storage.LoginStateDatatype, storage.DefaultRealm, storage.DefaultUser, state, storage.LatestRev, &loginState)
	if err != nil {
		httputils.WriteError(w, status.Errorf(codes.Internal, "read login state failed, %q", err))
		return
	}

	if len(loginState.Challenge) == 0 {
		httputils.WriteError(w, status.Errorf(codes.PermissionDenied, "invalid login state challenge parameter"))
		return
	}

	// Report the login err to hydra.
	hyErr := &hydraapi.RequestDeniedError{
		Name:        errName,
		Description: errDesc,
	}
	resp, err := hydra.RejectLogin(s.httpClient, s.hydraAdminURL, loginState.Challenge, hyErr)
	if err != nil {
		httputils.WriteError(w, status.Errorf(codes.Unavailable, "%v", err))
		return
	}

	httputils.WriteRedirect(w, r, resp.RedirectTo)
}

// HydraConsent handles consent request from hydra.
func (s *Service) HydraConsent(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	redirect, out, err := s.hydraConsent(r)
	if err != nil {
		httputils.WriteError(w, err)
	}
	if redirect {
		httputils.WriteRedirect(w, r, out)
		return
	}
	httputils.WriteHTMLResp(w, out)
}

// hydraConsent returns:
//   if true, redirect address.
//   if false, the html page.
func (s *Service) hydraConsent(r *http.Request) (_ bool, _ string, ferr error) {

	// Use consent_challenge fetch information from hydra.
	challenge, sts := hydra.ExtractConsentChallenge(r)
	if sts != nil {
		return false, "", sts.Err()
	}

	consent, err := hydra.GetConsentRequest(s.httpClient, s.hydraAdminURL, challenge)
	if err != nil {
		return false, "", status.Errorf(codes.Unavailable, "%v", err)
	}

	yes, redirect, err := hydra.ConsentSkip(r, s.httpClient, consent, s.hydraAdminURL, challenge)
	if err != nil {
		return false, "", status.Errorf(codes.Unavailable, "%v", err)
	}
	if yes {
		return true, redirect, nil
	}

	clientName := consent.Client.Name
	if len(clientName) == 0 {
		clientName = consent.Client.ClientID
	}
	if len(clientName) == 0 {
		return false, "", status.Errorf(codes.Unavailable, "consent.Client.Name empty")
	}

	sub := consent.Subject
	if len(sub) == 0 {
		return false, "", status.Errorf(codes.Unavailable, "consent.Subject empty")
	}

	stateID, sts := hydra.ExtractStateIDInConsent(consent)
	if sts != nil {
		return false, "", sts.Err()
	}

	tx, err := s.store.Tx(true)
	if err != nil {
		return false, "", status.Errorf(codes.Unavailable, "%v", err)
	}
	defer func() {
		err := tx.Finish()
		if ferr == nil {
			ferr = err
		}
	}()

	state := &cpb.AuthTokenState{}
	err = s.store.ReadTx(storage.AuthTokenStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, state, tx)
	if err != nil {
		return false, "", status.Errorf(codes.Internal, "%v", err)
	}

	state.ConsentChallenge = challenge
	state.Scope = strings.Join(consent.RequestedScope, " ")
	state.Audience = append(consent.RequestedAudience, consent.Client.ClientID)
	err = s.store.WriteTx(storage.AuthTokenStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, state, nil, tx)
	if err != nil {
		return false, "", status.Errorf(codes.Internal, "%v", err)
	}
	a, err := auth.FromContext(r.Context())
	if err != nil {
		return false, "", status.Errorf(codes.Internal, "%v", err)
	}

	acct, st, err := s.scim.LoadAccount(sub, state.Realm, a.IsAdmin, tx)
	if err != nil {
		return false, "", status.Errorf(httputils.RPCCode(st), "%v", err)
	}

	cfg, err := s.loadConfig(tx, state.Realm)
	if err != nil {
		return false, "", status.Errorf(codes.Unavailable, "%v", err)
	}

	secrets, err := s.loadSecrets(tx)
	if err != nil {
		return false, "", status.Errorf(codes.Unavailable, "%v", err)
	}

	id, err := s.accountToIdentity(r.Context(), acct, cfg, secrets)
	if err != nil {
		return false, "", status.Errorf(codes.Internal, "%v", err)
	}

	id.Scope = strings.Join(consent.RequestedScope, " ")

	page := s.informationReleasePage(id, stateID, clientName, id.Scope, state.Realm, cfg)
	return false, page, nil
}

// hydraRejectConsent returns the redirect address.
func (s *Service) hydraRejectConsent(r *http.Request, stateID string) (_ string, ferr error) {
	tx, err := s.store.Tx(true)
	if err != nil {
		return "", status.Errorf(codes.Unavailable, "%v", err)
	}
	defer func() {
		err := tx.Finish()
		if ferr == nil {
			ferr = err
		}
	}()

	state := &cpb.AuthTokenState{}
	err = s.store.ReadTx(storage.AuthTokenStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, state, tx)
	if err != nil {
		return "", status.Errorf(codes.Internal, "%v", err)
	}

	// The temporary state for information releasing process can be only used once.
	err = s.store.DeleteTx(storage.AuthTokenStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, tx)
	if err != nil {
		return "", status.Errorf(codes.Internal, "%v", err)
	}

	req := &hydraapi.RequestDeniedError{
		Code:        http.StatusUnauthorized,
		Name:        "Consent Denied",
		Description: "User deny consent",
	}

	resp, err := hydra.RejectConsent(s.httpClient, s.hydraAdminURL, state.ConsentChallenge, req)
	if err != nil {
		return "", status.Errorf(codes.Unavailable, "%v", err)
	}

	return resp.RedirectTo, nil
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

func (s *Service) hydraAcceptConsent(r *http.Request, state *cpb.AuthTokenState, cfg *pb.IcConfig, tx storage.Tx) (string, error) {
	secrets, err := s.loadSecrets(tx)
	if err != nil {
		return "", status.Errorf(codes.Unavailable, "%v", err)
	}
	a, err := auth.FromContext(r.Context())
	if err != nil {
		return "", status.Errorf(codes.Internal, "%v", err)
	}

	acct, st, err := s.scim.LoadAccount(state.Subject, state.Realm, a.IsAdmin, tx)
	if err != nil {
		return "", status.Errorf(httputils.RPCCode(st), "%v", err)
	}

	id, err := s.accountToIdentity(r.Context(), acct, cfg, secrets)
	if err != nil {
		return "", status.Errorf(codes.Internal, "%v", err)
	}

	now := time.Now().Unix()

	// TODO: scope maybe different after optional information release.
	// scope down the identity.
	scoped := scopedIdentity(id, state.Scope, s.getIssuerString(), state.Subject, "", now, id.NotBefore, id.Expiry, []string{}, "")
	m, err := identityToHydraMap(scoped)
	if err != nil {
		return "", status.Errorf(codes.Internal, "%v", err)
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

	if len(scoped.Identities) != 0 {
		var identities []string
		for k := range scoped.Identities {
			identities = append(identities, k)
		}

		req.Session.AccessToken["identities"] = identities
	}

	resp, err := hydra.AcceptConsent(s.httpClient, s.hydraAdminURL, state.ConsentChallenge, req)
	if err != nil {
		return "", status.Errorf(codes.Unavailable, "%v", err)
	}

	return resp.RedirectTo, nil
}

// HydraOAuthToken proxy the POST /oauth2/token request.
// - for code exhange token: do nothing, just proxy.
// - for refresh token exchange token: check the token is not revoked before proxy the request.
// TODO: should unify with HydraOAuthToken in DAM.
func (s *Service) HydraOAuthToken(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	// introspect the refresh token before proxy the request to exchange.
	if isRefreshTokenExchange(r) {
		deleted, err := s.tokenDeleted(r.PostFormValue("refresh_token"))
		if err != nil {
			httputils.WriteError(w, err)
			return
		}
		if deleted {
			httputils.WriteError(w, status.Errorf(codes.Unauthenticated, "token revoked"))
			return
		}
	}

	// Encode form back into request body
	r.Body = ioutil.NopCloser(bytes.NewBufferString(r.PostForm.Encode()))

	s.HydraPublicURLProxy.ServeHTTP(w, r)
}

func isRefreshTokenExchange(r *http.Request) bool {
	return r.PostFormValue("grant_type") == "refresh_token"
}

// tokenRevoked checks if token is in pending delete state, if it is in pending delete state, revoke it from hydra.
// Returns deleted and error
func (s *Service) tokenDeleted(refreshToken string) (_ bool, ferr error) {
	if len(refreshToken) == 0 {
		return false, status.Error(codes.FailedPrecondition, "no refresh_token")
	}

	in, err := hydra.Introspect(s.httpClient, s.hydraAdminURL, refreshToken)
	if err != nil {
		return false, err
	}

	tid, err := hydra.ExtractTokenIDInIntrospect(in)
	if err != nil {
		return false, err
	}

	tx, err := s.store.Tx(true)
	if err != nil {
		return false, status.Errorf(codes.Unavailable, "tokenDeleted: can not get tx: %v", err)
	}
	defer func() {
		err := tx.Finish()
		if ferr == nil {
			ferr = err
		}
	}()

	pending := &tpb.PendingDeleteToken{}
	err = s.store.ReadTx(storage.PendingDeleteTokenDatatype, storage.DefaultRealm, in.Subject, tid, storage.LatestRev, pending, tx)
	if err != nil {
		// No pending delete for this token.
		if storage.ErrNotFound(err) {
			return false, nil
		}
		return false, status.Errorf(codes.Unavailable, "tokenDeleted: read PendingDeleteToken failed: %v", err)
	}

	// delete this token
	if err := hydra.RevokeToken(s.httpClient, s.hydraAdminURL, refreshToken); err != nil {
		return false, err
	}

	if err := s.store.DeleteTx(storage.PendingDeleteTokenDatatype, storage.DefaultRealm, in.Subject, tid, storage.LatestRev, tx); err != nil {
		return false, status.Errorf(codes.Unavailable, "tokenDeleted: delete PendingDeleteToken failed: %v", err)
	}

	return true, nil
}
