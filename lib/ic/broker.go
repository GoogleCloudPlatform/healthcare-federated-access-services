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
	"github.com/pborman/uuid" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/errutil" /* copybara-comment: errutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/globalflags" /* copybara-comment: globalflags */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/hydra" /* copybara-comment: hydra */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/ic/v1" /* copybara-comment: go_proto */
)

// Login is the HTTP handler for ".../login/{name}" endpoint.
func (s *Service) Login(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	challenge := httputils.QueryParam(r, "login_challenge")
	if s.useHydra {
		if len(challenge) == 0 {
			httputils.WriteError(w, status.Errorf(codes.InvalidArgument, "Query login_challenge missing"))
			return
		}
	} else {
		httputils.WriteError(w, status.Errorf(codes.Unimplemented, "Unimplemented oidc provider"))
	}

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
		challenge: challenge,
	}

	redirect, err := s.login(in, cfg)
	if err == nil {
		httputils.WriteRedirect(w, r, redirect)
		return
	}

	if s.useHydra {
		hydra.SendLoginReject(w, r, s.httpClient, s.hydraAdminURL, challenge, err)
	} else {
		httputils.WriteError(w, err)
	}
}

// AcceptLogin is the HTTP handler for ".../loggedin/{name}" endpoint.
func (s *Service) AcceptLogin(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	stateParam := httputils.QueryParam(r, "state")
	errStr := httputils.QueryParam(r, "error")
	errDesc := httputils.QueryParam(r, "error_description")

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

	if s.useHydra && len(loginState.Challenge) == 0 {
		httputils.WriteError(w, status.Errorf(codes.Internal, "invalid login state parameter"))
		return
	}

	redirect, err := s.acceptLogin(r, &loginState, errStr, errDesc)
	if err == nil {
		httputils.WriteRedirect(w, r, redirect)
		return
	}

	if s.useHydra {
		hydra.SendLoginReject(w, r, s.httpClient, s.hydraAdminURL, loginState.Challenge, err)
	} else {
		httputils.WriteError(w, err)
	}
}

// acceptLogin returns redirect and status error
func (s *Service) acceptLogin(r *http.Request, state *cpb.LoginState, errStr, errDesc string) (string, error) {
	if len(errStr) > 0 || len(errDesc) > 0 {
		return "", errutil.WithErrorReason(errStr, status.Errorf(codes.Unauthenticated, errDesc))
	}

	if len(state.IdpName) == 0 || len(state.Realm) == 0 {
		return "", status.Errorf(codes.PermissionDenied, "invalid login state parameter")
	}

	// For the purposes of simplifying OIDC redirect_uri registrations, this handler is on a path without
	// realms or other query param context. To make the handling of these requests compatible with the
	// rest of the code, this request will be forwarded to a standard path at "finishLoginPath" and state
	// parameters received from the OIDC call flow will be normalized into query parameters.
	path := strings.Replace(finishLoginPath, "{realm}", state.Realm, -1)
	path = strings.Replace(path, "{name}", state.IdpName, -1)

	u, err := url.Parse(path)
	if err != nil {
		return "", status.Errorf(codes.Internal, "bad redirect format: %v", err)
	}
	u.RawQuery = r.URL.RawQuery
	return u.String(), nil
}

// FinishLogin is the HTTP handler for ".../loggedin" endpoint.
func (s *Service) FinishLogin(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	challenge, res, err := s.doFinishLogin(r)
	if err == nil {
		res.writeResp(w, r)
		return
	}

	if s.useHydra && len(challenge) > 0 {
		hydra.SendLoginReject(w, r, s.httpClient, s.hydraAdminURL, challenge, err)
	} else {
		httputils.WriteError(w, err)
	}
}

// doFinishLogin returns challenge, redirect or html page and status error.
func (s *Service) doFinishLogin(r *http.Request) (_ string, _ *htmlPageOrRedirectURL, ferr error) {
	r.ParseForm()

	tx, err := s.store.Tx(true)
	if err != nil {
		return "", nil, status.Errorf(codes.Unavailable, "%v", err)
	}
	defer func() {
		err := tx.Finish()
		if ferr == nil && err != nil {
			ferr = status.Errorf(codes.Internal, "%v", err)
		}
	}()

	cfg, err := s.loadConfig(tx, getRealm(r))
	if err != nil {
		return "", nil, status.Errorf(codes.Unavailable, "%v", err)
	}
	idpName := getName(r)
	idp, ok := cfg.IdentityProviders[idpName]
	if !ok {
		return "", nil, status.Errorf(codes.Unauthenticated, "invalid identity provider %q", idpName)
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
			return "", &htmlPageOrRedirectURL{page: page}, nil
		}
	} else {
		// Experimental allows non OIDC auth code flow which code or stateParam can be empty.
		if len(code) == 0 || len(stateParam) == 0 {
			return "", nil, status.Errorf(codes.Unauthenticated, "query params code or state missing")
		}
	}

	var loginState cpb.LoginState
	err = s.store.ReadTx(storage.LoginStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateParam, storage.LatestRev, &loginState, tx)
	if err != nil {
		return "", nil, status.Errorf(codes.Internal, "read login state failed, %q", err)
	}
	// state should be one time usage.
	err = s.store.DeleteTx(storage.LoginStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateParam, storage.LatestRev, tx)
	if err != nil {
		return "", nil, status.Errorf(codes.Internal, "delete login state failed, %q", err)
	}

	challenge := loginState.Challenge

	if s.useHydra {
		if len(loginState.Challenge) == 0 {
			return "", nil, status.Errorf(codes.Unauthenticated, "invalid login state parameter")
		}
	} else {
		return "", nil, status.Errorf(codes.Unimplemented, "Unimplemented oidc provider")
	}

	if len(loginState.IdpName) == 0 || len(loginState.Realm) == 0 {
		return challenge, nil, status.Errorf(codes.Unauthenticated, "invalid login state parameter")
	}

	if len(code) == 0 && len(idToken) == 0 && !s.idpUsesClientLoginPage(loginState.IdpName, loginState.Realm, cfg) {
		return challenge, nil, status.Errorf(codes.Unauthenticated, "missing auth code")
	}

	if idpName != loginState.IdpName {
		return challenge, nil, status.Errorf(codes.Unauthenticated, "request idp does not match login state, want %q, got %q", loginState.IdpName, idpName)
	}

	secrets, err := s.loadSecrets(tx)
	if err != nil {
		return challenge, nil, status.Errorf(codes.Unavailable, "%v", err)
	}
	if len(accessToken) == 0 {
		idpc := idpConfig(idp, s.getDomainURL(), secrets)
		tok, err := idpc.Exchange(r.Context(), code)
		if err != nil {
			return challenge, nil, status.Errorf(codes.Unauthenticated, "invalid code: %v", err)
		}
		accessToken = tok.AccessToken
		if len(idToken) == 0 {
			idToken, ok = tok.Extra("id_token").(string)
			if !ok && len(accessToken) == 0 {
				return challenge, nil, status.Errorf(codes.Unauthenticated, "identity provider response does not contain an access_token nor id_token token")
			}
		}
	}

	login, st, err := s.loginTokenToIdentity(accessToken, idToken, idp, r, cfg, secrets)
	if err != nil {
		return challenge, nil, status.Errorf(httputils.RPCCode(st), "%v", err)
	}

	res, err := s.finishLogin(login, idpName, loginState.Challenge, tx, cfg, secrets, r)
	return challenge, res, err
}

// finishLogin returns html page or redirect url and status error
func (s *Service) finishLogin(id *ga4gh.Identity, provider, challenge string, tx storage.Tx, cfg *pb.IcConfig, secrets *pb.IcSecrets, r *http.Request) (*htmlPageOrRedirectURL, error) {
	realm := getRealm(r)
	lookup, err := s.scim.LoadAccountLookup(realm, id.Subject, tx)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "%v", err)
	}
	var subject string
	if isLookupActive(lookup) {
		subject = lookup.Subject
		acct, _, err := s.scim.LoadAccount(subject, realm, true, tx)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "%v", err)
		}
		if acct.State == storage.StateDisabled {
			// Reject using a DISABLED account.
			return nil, status.Errorf(codes.PermissionDenied, "this account has been disabled, please contact the system administrator")
		}
		visas, err := s.accountLinkToVisas(r.Context(), acct, id.Subject, provider, cfg, secrets)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "%v", err)
		}
		if !visasAreEqual(visas, id.VisaJWTs) {
			// Refresh the claims in the storage layer.
			if err := s.populateAccountVisas(r.Context(), acct, id, provider); err != nil {
				return nil, status.Errorf(codes.Unavailable, "%v", err)
			}
			err := s.scim.SaveAccount(nil, acct, "REFRESH claims "+id.Subject, r, id.Subject, tx)
			if err != nil {
				return nil, status.Errorf(codes.Unavailable, "%v", err)
			}
		}
	} else {
		// Create an account for the identity automatically.
		acct, err := s.newAccountWithLink(r.Context(), id, provider, cfg)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "%v", err)
		}

		if err = s.saveNewLinkedAccount(acct, id, "New Account", r, tx, lookup); err != nil {
			return nil, status.Errorf(codes.Unavailable, "%v", err)
		}
		subject = acct.Properties.Subject
	}

	loginHint := makeLoginHint(provider, id.Subject)

	// redirect to information release page.
	auth := &cpb.AuthTokenState{
		Subject:   subject,
		Provider:  provider,
		Realm:     realm,
		LoginHint: loginHint,
	}

	stateID := uuid.New()

	err = s.store.WriteTx(storage.AuthTokenStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, auth, nil, tx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}

	if s.useHydra {
		// send login success to hydra and redirect to hydra, hydra will come back to /identity/consent for information release.
		redirect, err := hydra.LoginSuccess(r, s.httpClient, s.hydraAdminURL, challenge, subject, stateID, nil)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "%v", err)
		}
		return &htmlPageOrRedirectURL{redirect: redirect}, nil
	}

	return nil, status.Errorf(codes.Unimplemented, "Unimplemented oidc provider")
}

// AcceptInformationRelease is the HTTP handler for ".../inforelease" endpoint.
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
		return "", "", status.Errorf(codes.Unavailable, "%v", err)
	}
	defer func() {
		err := tx.Finish()
		if ferr == nil && err != nil {
			ferr = status.Errorf(codes.Internal, "%v", err)
		}
	}()

	state := &cpb.AuthTokenState{}
	err = s.store.ReadTx(storage.AuthTokenStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, state, tx)
	if err != nil {
		return "", "", status.Errorf(codes.Internal, "%v", err)
	}

	// The temporary state for information releasing process can be only used once.
	err = s.store.DeleteTx(storage.AuthTokenStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, tx)
	if err != nil {
		return "", "", status.Errorf(codes.Internal, "%v", err)
	}

	challenge := state.ConsentChallenge

	agree := httputils.QueryParam(r, "agree")
	if agree != "y" {
		return challenge, "", errutil.WithErrorReason("user_denied", status.Errorf(codes.Unauthenticated, "User deny consent"))
	}

	cfg, err := s.loadConfig(tx, state.Realm)
	if err != nil {
		return challenge, "", status.Errorf(codes.Internal, "%v", err)
	}

	if s.useHydra {
		addr, err := s.hydraAcceptConsent(r, state, cfg, tx)
		if err != nil {
			return challenge, "", status.Errorf(codes.Internal, "%v", err)
		}
		return challenge, addr, nil
	}

	return challenge, "", status.Errorf(codes.Unimplemented, "oidc service not supported")
}
