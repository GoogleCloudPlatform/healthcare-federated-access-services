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
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/adapter"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common"

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1"
)

// GetResourceToken implements endpoint "resources/{name}/views/{view}/token" or
// "resources/{name}/views/{view}/roles/{role}/token".
func (s *Service) GetResourceToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request method %s not allowed", r.Method), w)
		return
	}
	vars := mux.Vars(r)
	name := vars["name"]
	viewName := vars["view"]
	role := vars["role"]
	if err := checkName(name); err != nil {
		common.HandleError(http.StatusBadRequest, err, w)
		return
	}
	if err := checkName(viewName); err != nil {
		common.HandleError(http.StatusBadRequest, err, w)
		return
	}
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	res, ok := cfg.Resources[name]
	if !ok {
		common.HandleError(http.StatusNotFound, fmt.Errorf("resource not found: %q", name), w)
		return
	}
	id, status, err := s.getPassportIdentity(cfg, nil, r)
	if err != nil {
		common.HandleError(status, err, w)
		return
	}
	view, ok := res.Views[viewName]
	if !ok {
		common.HandleError(http.StatusNotFound, fmt.Errorf("view %q not found for resource %q", viewName, name), w)
		return
	}
	grantRole := role
	if len(grantRole) == 0 {
		grantRole = view.DefaultRole
	}

	ttl := defaultTTL
	if ttlStr := r.URL.Query().Get("ttl"); len(ttlStr) > 0 {
		ttl, err = common.ParseDuration(ttlStr, defaultTTL)
		if err != nil {
			common.HandleError(http.StatusBadRequest, fmt.Errorf("TTL parameter %q format error: %v", ttlStr, err), w)
			return
		}
		if ttl == 0 {
			ttl = defaultTTL
		} else if ttl < 0 || ttl > maxTTL {
			common.HandleError(http.StatusBadRequest, fmt.Errorf("TTL parameter %q out of range: must be positive and not exceed %s", ttlStr, maxTTLStr), w)
			return
		}
	}

	status, err = s.checkAuthorization(id, ttl, name, viewName, grantRole, cfg, getClientID(r), nil)
	if err != nil {
		common.HandleError(status, err, w)
		return
	}

	sRole, err := adapter.ResolveServiceRole(grantRole, view, res, cfg)
	if err != nil {
		common.HandleError(http.StatusInternalServerError, err, w)
		return
	}
	if !viewHasRole(view, grantRole) {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("role %q is not defined on resource %q view %q", grantRole, name, viewName), w)
		return
	}
	st, ok := cfg.ServiceTemplates[view.ServiceTemplate]
	if !ok {
		common.HandleError(http.StatusInternalServerError, fmt.Errorf("view %q service template %q is not defined", viewName, view.ServiceTemplate), w)
		return
	}
	adapt := s.adapters.ByName[st.TargetAdapter]
	var aggregates []*adapter.AggregateView
	if adapt.IsAggregator() {
		aggregates, err = s.resolveAggregates(res, view, cfg)
		if err != nil {
			common.HandleError(http.StatusInternalServerError, err, w)
			return
		}
	}
	keyFile := false
	tokenFormat := ""
	if common.GetParam(r, "response_type") == "key-file-type" {
		keyFile = true
		tokenFormat = "application/json"
	}
	adapterAction := &adapter.Action{
		Aggregates:      aggregates,
		Identity:        id,
		Issuer:          getIssuerString(r),
		ClientID:        getClientID(r),
		Config:          cfg,
		GrantRole:       grantRole,
		MaxTTL:          maxTTL,
		Resource:        res,
		ServiceRole:     sRole,
		ServiceTemplate: st,
		TTL:             ttl,
		View:            view,
		TokenFormat:     tokenFormat,
	}
	result, err := adapt.MintToken(r.Context(), adapterAction)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}

	if keyFile {
		if common.IsJSON(result.TokenFormat) {
			common.SendJSONResponse(result.Token, w)
			return
		}
		common.HandleError(http.StatusBadRequest, fmt.Errorf("adapter cannot create key file format"), w)
	}
	out := &pb.GetTokenResponse{
		Name:    name,
		View:    s.makeView(viewName, view, res, cfg),
		Account: result.Account,
		Token:   result.Token,
		Ttl:     common.TtlString(ttl),
	}
	common.SendResponse(out, w)
}
