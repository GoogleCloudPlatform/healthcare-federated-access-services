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
	"net/url"
	"strings"

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common" /* copybara-comment: common */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
)

// Login is the HTTP handler for ".../login/{name}" endpoint.
func (s *Service) Login(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	scope, err := getScope(r)
	if err != nil {
		common.HandleError(http.StatusBadRequest, err, w)
		return
	}

	realm := getRealm(r)

	cfg, err := s.loadConfig(nil, realm)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}

	in := loginIn{
		realm:     realm,
		scope:     strings.Split(scope, " "),
		loginHint: common.GetParam(r, "login_hint"),
		idpName:   getName(r),
		challenge: common.GetParam(r, "login_challenge"),
	}

	s.login(in, w, r, cfg)
}

// AcceptLogin is the HTTP handler for ".../loggedin/{name}" endpoint.
func (s *Service) AcceptLogin(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	stateParam := common.GetParam(r, "state")
	errStr := common.GetParam(r, "error")
	errDesc := common.GetParam(r, "error_description")
	if len(errStr) > 0 || len(errDesc) > 0 {
		if s.useHydra && len(stateParam) > 0 {
			s.hydraLoginError(w, r, stateParam, errStr, errDesc)
			return
		}
		common.HandleError(http.StatusUnauthorized, fmt.Errorf("authorization error: %q, description: %q", errStr, errDesc), w)
		return
	}

	extract := common.GetParam(r, "client_extract") // makes sure we only grab state from client once

	// Some IdPs need state extracted from html anchor.
	if len(stateParam) == 0 && len(extract) == 0 {
		page := s.clientLoginPage
		page = strings.Replace(page, "${INSTRUCTIONS}", `""`, -1)
		page = pageVariableRE.ReplaceAllString(page, `""`)
		common.SendHTML(page, w)
		return
	}

	var loginState cpb.LoginState
	err := s.store.Read(storage.LoginStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateParam, storage.LatestRev, &loginState)
	if err != nil {
		common.HandleError(http.StatusInternalServerError, fmt.Errorf("read login state failed, %q", err), w)
		return
	}
	if len(loginState.IdpName) == 0 || len(loginState.Realm) == 0 {
		common.HandleError(http.StatusUnauthorized, fmt.Errorf("invalid login state parameter"), w)
		return
	}
	if s.useHydra && len(loginState.Challenge) == 0 {
		common.HandleError(http.StatusUnauthorized, fmt.Errorf("invalid login state parameter"), w)
		return
	}

	// For the purposes of simplifying OIDC redirect_uri registrations, this handler is on a path without
	// realms or other query param context. To make the handling of these requests compatible with the
	// rest of the code, this request will be forwarded to a standard path at "finishLoginPath" and state
	// parameters received from the OIDC call flow will be normalized into query parameters.
	path := strings.Replace(finishLoginPath, "{realm}", loginState.Realm, -1)
	path = strings.Replace(path, "{name}", loginState.IdpName, -1)

	u, err := url.Parse(path)
	if err != nil {
		common.HandleError(http.StatusInternalServerError, fmt.Errorf("bad redirect format: %v", err), w)
		return
	}
	u.RawQuery = r.URL.RawQuery
	common.SendRedirect(u.String(), r, w)
}

// FinishLogin is the HTTP handler for ".../loggedin" endpoint.
func (s *Service) FinishLogin(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	code := common.GetParam(r, "code")
	idToken := common.GetParam(r, "id_token")
	accessToken := common.GetParam(r, "access_token")
	stateParam := common.GetParam(r, "state")
	extract := common.GetParam(r, "client_extract") // makes sure we only grab state from client once

	tx, err := s.store.Tx(true)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	defer tx.Finish()

	cfg, err := s.loadConfig(tx, getRealm(r))
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	idpName := getName(r)
	idp, ok := cfg.IdentityProviders[idpName]
	if !ok {
		common.HandleError(http.StatusUnauthorized, fmt.Errorf("invalid identity provider %q", idpName), w)
		return
	}

	if len(extract) == 0 && len(code) == 0 && len(idToken) == 0 && len(accessToken) == 0 {
		instructions := ""
		if len(idp.TokenUrl) > 0 && !strings.HasPrefix(idp.TokenUrl, "http") {
			// Allow the client login page to follow instructions encoded in the TokenUrl.
			// This enables support for some non-OIDC clients.
			instructions = `"` + idp.TokenUrl + `"`
		}
		page := s.clientLoginPage
		page = strings.Replace(page, "${INSTRUCTIONS}", instructions, -1)
		page = pageVariableRE.ReplaceAllString(page, `""`)
		common.SendHTML(page, w)
		return
	}

	var loginState cpb.LoginState
	err = s.store.ReadTx(storage.LoginStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateParam, storage.LatestRev, &loginState, tx)
	if err != nil {
		common.HandleError(http.StatusInternalServerError, fmt.Errorf("read login state failed, %q", err), w)
		return
	}
	// state should be one time usage.
	err = s.store.DeleteTx(storage.LoginStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateParam, storage.LatestRev, tx)
	if err != nil {
		common.HandleError(http.StatusInternalServerError, fmt.Errorf("delete login state failed, %q", err), w)
		return
	}

	// TODO: add security checks here as per OIDC spec.
	if len(loginState.IdpName) == 0 || len(loginState.Realm) == 0 {
		common.HandleError(http.StatusUnauthorized, fmt.Errorf("invalid login state parameter"), w)
		return
	}

	if s.useHydra {
		if len(loginState.Challenge) == 0 {
			common.HandleError(http.StatusUnauthorized, fmt.Errorf("invalid login state parameter"), w)
			return
		}
	} else {
		if len(loginState.ClientId) == 0 || len(loginState.Redirect) == 0 || len(loginState.Nonce) == 0 {
			common.HandleError(http.StatusUnauthorized, fmt.Errorf("invalid login state parameter"), w)
			return
		}
	}

	if len(code) == 0 && len(idToken) == 0 && !s.idpUsesClientLoginPage(loginState.IdpName, loginState.Realm, cfg) {
		common.HandleError(http.StatusUnauthorized, fmt.Errorf("missing auth code"), w)
		return
	}

	redirect := loginState.Redirect
	scope := loginState.Scope
	state := loginState.State
	nonce := loginState.Nonce
	clientID := loginState.ClientId

	if idpName != loginState.IdpName {
		common.HandleError(http.StatusUnauthorized, fmt.Errorf("request idp does not match login state, want %q, got %q", loginState.IdpName, idpName), w)
		return
	}

	secrets, err := s.loadSecrets(tx)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	if len(accessToken) == 0 {
		idpc := idpConfig(idp, s.getDomainURL(), secrets)
		tok, err := idpc.Exchange(r.Context(), code)
		if err != nil {
			common.HandleError(http.StatusUnauthorized, fmt.Errorf("invalid code: %v", err), w)
			return
		}
		accessToken = tok.AccessToken
		if len(idToken) == 0 {
			idToken, ok = tok.Extra("id_token").(string)
			if !ok && len(accessToken) == 0 {
				common.HandleError(http.StatusUnauthorized, fmt.Errorf("identity provider response does not contain an access_token nor id_token token"), w)
				return
			}
		}
	}

	login, status, err := s.loginTokenToIdentity(accessToken, idToken, idp, r, cfg, secrets)
	if err != nil {
		common.HandleError(status, err, w)
		return
	}

	// If Idp does not support nonce field, use nonce in state instead.
	if len(login.Nonce) == 0 {
		login.Nonce = nonce
	}
	if nonce != login.Nonce {
		common.HandleError(status, fmt.Errorf("nonce in id token is not equal to nonce linked to auth code"), w)
		return
	}

	s.finishLogin(login, idpName, redirect, scope, clientID, state, loginState.Challenge, tx, cfg, secrets, r, w)
}

// AcceptInformationRelease is the HTTP handler for ".../inforelease" endpoint.
func (s *Service) AcceptInformationRelease(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	stateID := common.GetParam(r, "state")
	if len(stateID) == 0 {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("missing %q parameter", "state"), w)
		return
	}

	agree := common.GetParam(r, "agree")
	if agree != "y" {
		if s.useHydra {
			s.hydraRejectConsent(w, r, stateID)
			return
		}

		common.HandleError(http.StatusUnauthorized, fmt.Errorf("no information release"), w)
		return
	}

	tx, err := s.store.Tx(true)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	defer tx.Finish()

	state := &cpb.AuthTokenState{}
	err = s.store.ReadTx(storage.AuthTokenStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, state, tx)
	if err != nil {
		common.HandleError(http.StatusInternalServerError, err, w)
		return
	}

	err = s.store.DeleteTx(storage.AuthTokenStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, tx)
	if err != nil {
		common.HandleError(http.StatusInternalServerError, err, w)
		return
	}

	cfg, err := s.loadConfig(tx, state.Realm)
	if err != nil {
		common.HandleError(http.StatusInternalServerError, err, w)
		return
	}

	if s.useHydra {
		s.hydraAcceptConsent(w, r, state, cfg, tx)
		return
	}

	httputil.WriteStatus(w, status.New(codes.Unimplemented, "oidc service not supported"))
}
