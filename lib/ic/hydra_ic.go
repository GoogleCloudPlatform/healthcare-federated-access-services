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
	"os"
	"strings"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/apis/hydraapi"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/hydra"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage"

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1"
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/ic/v1"
)

// HydraLogin handles login request from hydra.
func (s *Service) HydraLogin(w http.ResponseWriter, r *http.Request) {
	// Use login_challenge fetch information from hydra.
	challenge, status := hydra.ExtractLoginChallenge(r)
	if status != nil {
		httputil.WriteStatus(w, status)
		return
	}

	login, err := hydra.GetLoginRequest(s.httpClient, s.hydraAdminURL, challenge)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}

	if hydra.LoginSkip(w, r, s.httpClient, login, s.hydraAdminURL, challenge) {
		return
	}

	u, err := url.Parse(login.RequestURL)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}

	realm := u.Query().Get("realm")
	if len(realm) == 0 {
		realm = storage.DefaultRealm
	}

	cfg, err := s.loadConfig(nil, realm)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}

	scopes := login.RequestedScope
	if len(scopes) == 0 {
		scopes = defaultIdpScopes
	}

	// Return Login page.
	query := fmt.Sprintf("?scope=%s&login_challenge=%s", url.QueryEscape(strings.Join(scopes, " ")), url.QueryEscape(challenge))
	page, err := s.renderLoginPage(cfg, map[string]string{"realm": realm}, query)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	common.SendHTML(page, w)
}

func (s *Service) hydraLoginError(w http.ResponseWriter, r *http.Request, state, errName, errDesc string) {
	var loginState cpb.LoginState
	err := s.store.Read(storage.LoginStateDatatype, storage.DefaultRealm, storage.DefaultUser, state, storage.LatestRev, &loginState)
	if err != nil {
		common.HandleError(http.StatusInternalServerError, fmt.Errorf("read login state failed, %q", err), w)
		return
	}

	if len(loginState.Challenge) == 0 {
		common.HandleError(http.StatusUnauthorized, fmt.Errorf("invalid login state challenge parameter"), w)
		return
	}

	// Report the login err to hydra.
	hyErr := &hydraapi.RequestDeniedError{
		Name:        errName,
		Description: errDesc,
	}
	resp, err := hydra.RejectLoginRequest(s.httpClient, s.hydraAdminURL, loginState.Challenge, hyErr)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}

	common.SendRedirect(resp.RedirectTo, r, w)
}

// HydraConsent handles consent request from hydra.
func (s *Service) HydraConsent(w http.ResponseWriter, r *http.Request) {
	// Use consent_challenge fetch information from hydra.
	challenge, status := hydra.ExtractConsentChallenge(r)
	if status != nil {
		httputil.WriteStatus(w, status)
		return
	}

	consent, err := hydra.GetConsentRequest(s.httpClient, s.hydraAdminURL, challenge)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}

	if hydra.ConsentSkip(w, r, s.httpClient, consent, s.hydraAdminURL, challenge) {
		return
	}

	clientName := consent.Client.Name
	if len(clientName) == 0 {
		clientName = consent.Client.ClientID
	}
	if len(clientName) == 0 {
		common.HandleError(http.StatusServiceUnavailable, fmt.Errorf("consent.Client.Name empty"), w)
		return
	}

	sub := consent.Subject
	if len(sub) == 0 {
		common.HandleError(http.StatusServiceUnavailable, fmt.Errorf("consent.Subject empty"), w)
		return
	}

	stateID, status := hydra.ExtractStateIDInConsent(consent)
	if status != nil {
		httputil.WriteStatus(w, status)
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

	state.ConsentChallenge = challenge
	state.Scope = strings.Join(consent.RequestedScope, " ")
	state.Audience = append(consent.RequestedAudience, consent.Client.ClientID)
	err = s.store.WriteTx(storage.AuthTokenStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, state, nil, tx)
	if err != nil {
		common.HandleError(http.StatusInternalServerError, err, w)
		return
	}

	acct, st, err := s.loadAccount(sub, state.Realm, tx)
	if err != nil {
		common.HandleError(st, err, w)
		return
	}

	cfg, err := s.loadConfig(tx, state.Realm)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}

	secrets, err := s.loadSecrets(tx)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}

	id, err := s.accountToIdentity(s.ctx, acct, cfg, secrets)
	if err != nil {
		common.HandleError(http.StatusInternalServerError, err, w)
		return
	}

	id.Scope = strings.Join(consent.RequestedScope, " ")

	s.sendInformationReleasePage(id, stateID, clientName, id.Scope, state.Realm, cfg, w)
}

func (s *Service) hydraRejectConsent(w http.ResponseWriter, r *http.Request, stateID string) {
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

	// The temporary state for information releasing process can be only used once.
	err = s.store.DeleteTx(storage.AuthTokenStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, tx)
	if err != nil {
		common.HandleError(http.StatusInternalServerError, err, w)
		return
	}

	req := &hydraapi.RequestDeniedError{
		Code:        http.StatusUnauthorized,
		Name:        "Consent Denied",
		Description: "User deny consent",
	}

	resp, err := hydra.RejectConsentRequest(s.httpClient, s.hydraAdminURL, state.ConsentChallenge, req)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}

	common.SendRedirect(resp.RedirectTo, r, w)
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

func (s *Service) hydraAcceptConsent(w http.ResponseWriter, r *http.Request, state *cpb.AuthTokenState, cfg *pb.IcConfig, tx storage.Tx) {
	secrets, err := s.loadSecrets(tx)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}

	acct, status, err := s.loadAccount(state.Subject, state.Realm, tx)
	if err != nil {
		common.HandleError(status, err, w)
		return
	}

	id, err := s.accountToIdentity(s.ctx, acct, cfg, secrets)
	if err != nil {
		common.HandleError(http.StatusInternalServerError, err, w)
		return
	}

	now := common.GetNowInUnix()

	// TODO: scope maybe different after optional information release.
	// scope down the identity.
	scoped := scopedIdentity(id, state.Scope, s.getIssuerString(), state.Subject, "", now, id.NotBefore, id.Expiry, []string{}, "")
	m, err := identityToHydraMap(scoped)
	if err != nil {
		common.HandleError(http.StatusInternalServerError, err, w)
		return
	}

	req := &hydraapi.HandledConsentRequest{
		GrantedAudience: state.Audience,
		GrantedScope:    strings.Split(state.Scope, " "),
		Session: &hydraapi.ConsentRequestSessionData{
			IDToken: m,
		},
	}

	resp, err := hydra.AcceptConsentRequest(s.httpClient, s.hydraAdminURL, state.ConsentChallenge, req)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}

	common.SendRedirect(resp.RedirectTo, r, w)
}

// HydraTestPage send hydra test page.
func (s *Service) HydraTestPage(w http.ResponseWriter, r *http.Request) {
	hydraURL := os.Getenv("HYDRA_PUBLIC_URL")
	page := strings.ReplaceAll(s.hydraTestPage, "${HYDRA_URL}", hydraURL)
	common.SendHTML(page, w)
}
