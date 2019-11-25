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
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/hydra"

	glog "github.com/golang/glog"
)

const (
	stateIDInHydra = "state"
)

// HydraLogin handles login request from hydra.
func (s *Service) HydraLogin(w http.ResponseWriter, r *http.Request) {
	// Use login_challenge fetch information from hydra.
	challenge, err := hydra.ExtractLoginChallenge(r)
	if err != nil {
		common.HandleError(http.StatusBadRequest, err, w)
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

	ttl, err := extractTTL(u.Query().Get("max_age"), u.Query().Get("ttl"))
	if err != nil {
		common.HandleError(http.StatusBadRequest, err, w)
		return
	}

	list := u.Query()["resource"]
	resList, err := s.resourceViewRoleFromRequest(list)
	if err != nil {
		common.HandleError(http.StatusBadRequest, err, w)
		return
	}

	responseKeyFile := u.Query().Get("response_type") == "key-file-type"

	in := resourceAuthHandlerIn{
		ttl:             ttl,
		responseKeyFile: responseKeyFile,
		resources:       resList,
		challenge:       challenge,
	}

	out, status, err := s.resourceAuth(r.Context(), in)
	if err != nil {
		common.HandleError(status, err, w)
		return
	}

	auth := out.oauth.AuthCodeURL(out.stateID)

	sendRedirect(auth, r, w)
}

// HydraConsent handles consent request from hydra.
func (s *Service) HydraConsent(w http.ResponseWriter, r *http.Request) {
	glog.Errorln("unimplemented")
}

// HydraTestPage send hydra test page.
func (s *Service) HydraTestPage(w http.ResponseWriter, r *http.Request) {
	hydraURL := os.Getenv("HYDRA_PUBLIC_URL")
	page := strings.ReplaceAll(s.hydraTestPage, "${HYDRA_URL}", hydraURL)
	page = strings.ReplaceAll(page, "${DAM_URL}", s.domainURL)
	common.SendHTML(page, w)
}
