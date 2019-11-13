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
	"os"
	"strings"

	glog "github.com/golang/glog"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common"
)

// HydraLogin handles login request from hydra.
func (s *Service) HydraLogin(w http.ResponseWriter, r *http.Request) {
	glog.Errorln("unimplemented")
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
