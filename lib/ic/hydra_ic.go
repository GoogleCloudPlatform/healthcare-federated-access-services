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
	"os"
	"strings"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/apis/hydraapi"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/hydra"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage"

	glog "github.com/golang/glog"
	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1"
)

const (
	stateIDInHydra = "state"
)

// HydraLogin handles login request from hydra.
func (s *Service) HydraLogin(w http.ResponseWriter, r *http.Request) {
	// Use login_challenge fetch information from hydra.
	challenge, err := extractLoginChallenge(r)
	if err != nil {
		common.HandleError(http.StatusBadRequest, err, w)
		return
	}

	login, err := hydra.GetLoginRequest(s.httpClient, s.hydraAdminURL, challenge)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}

	// If hydra was already able to authenticate the user, skip will be true and we do not need to re-authenticate
	// the user.
	if login.Skip {
		// You can apply logic here, for example update the number of times the user logged in.

		// TODO: provide metrics / audit logs for this case

		// Now it's time to grant the login request. You could also deny the request if something went terribly wrong
		resp, err := hydra.AcceptLoginRequest(s.httpClient, s.hydraAdminURL, challenge, &hydraapi.HandledLoginRequest{Subject: &login.Subject})
		if err != nil {
			common.HandleError(http.StatusServiceUnavailable, err, w)
			return
		}

		common.SendRedirect(resp.RedirectTo, r, w)
		return
	}

	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
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

func (s *Service) hydraLoginSuccess(w http.ResponseWriter, r *http.Request, challenge, subject, stateID string) {
	req := &hydraapi.HandledLoginRequest{
		Subject: &subject,
		Context: map[string]interface{}{
			stateIDInHydra: stateID,
		},
	}
	resp, err := hydra.AcceptLoginRequest(s.httpClient, s.hydraAdminURL, challenge, req)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}

	common.SendRedirect(resp.RedirectTo, r, w)
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
	glog.Errorln("unimplemented")

}

// HydraTestPage send hydra test page.
func (s *Service) HydraTestPage(w http.ResponseWriter, r *http.Request) {
	hydraURL := os.Getenv("HYDRA_PUBLIC_URL")
	page := strings.ReplaceAll(s.hydraTestPage, "${HYDRA_URL}", hydraURL)
	common.SendHTML(page, w)
}
