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
	"net/http"
	"net/url"
	"strings"

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/globalflags" /* copybara-comment: globalflags */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
)

// Login is the HTTP handler for ".../login/{name}" endpoint.
func (s *Service) Login(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	scope, err := getScope(r)
	if err != nil {
		httputils.WriteError(w, status.Errorf(codes.InvalidArgument, "%v", err))
		return
	}

	realm := getRealm(r)

	cfg, err := s.loadConfig(nil, realm)
	if err != nil {
		httputils.WriteError(w, status.Errorf(codes.Unavailable, "%v", err))
		return
	}

	in := loginIn{
		realm:     realm,
		scope:     strings.Split(scope, " "),
		loginHint: httputils.QueryParam(r, "login_hint"),
		idpName:   getName(r),
		challenge: httputils.QueryParam(r, "login_challenge"),
	}

	s.login(in, w, r, cfg)
}

// AcceptLogin is the HTTP handler for ".../loggedin/{name}" endpoint.
func (s *Service) AcceptLogin(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	stateParam := httputils.QueryParam(r, "state")
	errStr := httputils.QueryParam(r, "error")
	errDesc := httputils.QueryParam(r, "error_description")
	if len(errStr) > 0 || len(errDesc) > 0 {
		if s.useHydra && len(stateParam) > 0 {
			s.hydraLoginError(w, r, stateParam, errStr, errDesc)
			return
		}
		httputils.WriteError(w, status.Errorf(codes.PermissionDenied, "authorization error: %q, description: %q", errStr, errDesc))
		return
	}

	// Experimental allows non OIDC auth code flow which may need state extracted from html anchor.
	if globalflags.Experimental {
		extract := httputils.QueryParam(r, "client_extract") // makes sure we only grab state from client once

		// Some IdPs need state extracted from html anchor.
		if len(stateParam) == 0 && len(extract) == 0 {
			page := s.clientLoginPage
			page = strings.Replace(page, "${INSTRUCTIONS}", `""`, -1)
			page = pageVariableRE.ReplaceAllString(page, `""`)
			httputils.WriteHTMLResp(w, page)
			return
		}
	}

	if len(stateParam) == 0 {
		httputils.WriteError(w, status.Errorf(codes.PermissionDenied, "query params state missing"))
		return
	}

	var loginState cpb.LoginState
	err := s.store.Read(storage.LoginStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateParam, storage.LatestRev, &loginState)
	if err != nil {
		httputils.WriteError(w, status.Errorf(codes.Internal, "read login state failed, %q", err))
		return
	}
	if len(loginState.IdpName) == 0 || len(loginState.Realm) == 0 {
		httputils.WriteError(w, status.Errorf(codes.PermissionDenied, "invalid login state parameter"))
		return
	}
	if s.useHydra && len(loginState.Challenge) == 0 {
		httputils.WriteError(w, status.Errorf(codes.PermissionDenied, "invalid login state parameter"))
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
		httputils.WriteError(w, status.Errorf(codes.Internal, "bad redirect format: %v", err))
		return
	}
	u.RawQuery = r.URL.RawQuery
	httputils.WriteRedirect(w, r, u.String())
}

// FinishLogin is the HTTP handler for ".../loggedin" endpoint.
func (s *Service) FinishLogin(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	redirect, out, err := s.doFinishLogin(r)
	if err != nil {
		httputils.WriteError(w, err)
	}
	if redirect {
		httputils.WriteRedirect(w, r, out)
	}
	httputils.WriteHTMLResp(w, out)
}

func (s *Service) doFinishLogin(r *http.Request) (_ bool, _ string, ferr error) {
	r.ParseForm()

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

	cfg, err := s.loadConfig(tx, getRealm(r))
	if err != nil {
		return false, "", status.Errorf(codes.Unavailable, "%v", err)
	}
	idpName := getName(r)
	idp, ok := cfg.IdentityProviders[idpName]
	if !ok {
		return false, "", status.Errorf(codes.Unauthenticated, "invalid identity provider %q", idpName)
		return
	}

	code := httputils.QueryParam(r, "code")
	stateParam := httputils.QueryParam(r, "state")
	idToken := ""
	accessToken := ""
	extract := ""
	// Experimental allows reading tokens from non-OIDC.
	if globalflags.Experimental {
		idToken = httputils.QueryParam(r, "id_token")
		accessToken = httputils.QueryParam(r, "access_token")
		extract = httputils.QueryParam(r, "client_extract") // makes sure we only grab state from client once

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
			return false, page, nil
		}
	} else {
		// Experimental allows non OIDC auth code flow which code or stateParam can be empty.
		if len(code) == 0 || len(stateParam) == 0 {
			return false, "", status.Errorf(codes.Unauthenticated, "query params code or state missing")
		}
	}

	var loginState cpb.LoginState
	err = s.store.ReadTx(storage.LoginStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateParam, storage.LatestRev, &loginState, tx)
	if err != nil {
		return false, "", status.Errorf(codes.Internal, "read login state failed, %q", err)
	}
	// state should be one time usage.
	err = s.store.DeleteTx(storage.LoginStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateParam, storage.LatestRev, tx)
	if err != nil {
		return false, "", status.Errorf(codes.Internal, "delete login state failed, %q", err)
	}

	// TODO: add security checks here as per OIDC spec.
	if len(loginState.IdpName) == 0 || len(loginState.Realm) == 0 {
		return false, "", status.Errorf(codes.Unauthenticated, "invalid login state parameter")
	}

	if s.useHydra {
		if len(loginState.Challenge) == 0 {
			return false, "", status.Errorf(codes.Unauthenticated, "invalid login state parameter")
		}
	} else {
		if len(loginState.ClientId) == 0 || len(loginState.Redirect) == 0 || len(loginState.Nonce) == 0 {
			return false, "", status.Errorf(codes.Unauthenticated, "invalid login state parameter")
		}
	}

	if len(code) == 0 && len(idToken) == 0 && !s.idpUsesClientLoginPage(loginState.IdpName, loginState.Realm, cfg) {
		return false, "", status.Errorf(codes.Unauthenticated, "missing auth code")
	}

	redirect := loginState.Redirect
	scope := loginState.Scope
	state := loginState.State
	nonce := loginState.Nonce
	clientID := loginState.ClientId

	if idpName != loginState.IdpName {
		return false, "", status.Errorf(codes.Unauthenticated, "request idp does not match login state, want %q, got %q", loginState.IdpName, idpName)
	}

	secrets, err := s.loadSecrets(tx)
	if err != nil {
		return false, "", status.Errorf(codes.Unavailable, "%v", err)
	}
	if len(accessToken) == 0 {
		idpc := idpConfig(idp, s.getDomainURL(), secrets)
		tok, err := idpc.Exchange(r.Context(), code)
		if err != nil {
			return false, "", status.Errorf(codes.Unauthenticated, "invalid code: %v", err)
		}
		accessToken = tok.AccessToken
		if len(idToken) == 0 {
			idToken, ok = tok.Extra("id_token").(string)
			if !ok && len(accessToken) == 0 {
				return false, "", status.Errorf(codes.Unauthenticated, "identity provider response does not contain an access_token nor id_token token")
			}
		}
	}

	login, st, err := s.loginTokenToIdentity(accessToken, idToken, idp, r, cfg, secrets)
	if err != nil {
		return false, "", status.Errorf(httputils.RPCCode(st), "%v", err)
	}

	// If Idp does not support nonce field, use nonce in state instead.
	if len(login.Nonce) == 0 {
		login.Nonce = nonce
	}
	if nonce != login.Nonce {
		return false, "", status.Errorf(httputils.RPCCode(st), "nonce in id token is not equal to nonce linked to auth code")
	}

	return s.finishLogin(login, idpName, redirect, scope, clientID, state, loginState.Challenge, tx, cfg, secrets, r)
}

// AcceptInformationRelease is the HTTP handler for ".../inforelease" endpoint.
func (s *Service) AcceptInformationRelease(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	redirect, out, err := s.acceptInformationRelease(r)
	if err != nil {
		httputils.WriteError(w, err)
	}
	if redirect {
		httputils.WriteRedirect(w, r, out)
	}
}

func (s *Service) acceptInformationRelease(r *http.Request) (_ bool, _ string, ferr error) {
	stateID := httputils.QueryParam(r, "state")
	if len(stateID) == 0 {
		return false, "", status.Errorf(codes.InvalidArgument, "missing %q parameter", "state")
	}

	agree := httputils.QueryParam(r, "agree")
	if agree != "y" {
		if s.useHydra {
			addr, err := s.hydraRejectConsent(r, stateID)
			if err != nil {
				return false, "", err
			}
			return true, addr, nil
		}
		return false, "", status.Errorf(codes.Unauthenticated, "no information release")
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

	err = s.store.DeleteTx(storage.AuthTokenStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, tx)
	if err != nil {
		return false, "", status.Errorf(codes.Internal, "%v", err)
	}

	cfg, err := s.loadConfig(tx, state.Realm)
	if err != nil {
		return false, "", status.Errorf(codes.Internal, "%v", err)
	}

	if s.useHydra {
		addr, err := s.hydraAcceptConsent(r, state, cfg, tx)
		if err != nil {
			return false, "", err
		}
		return true, addr, nil
	}

	return false, "", status.Errorf(codes.Unimplemented, "oidc service not supported")
}
