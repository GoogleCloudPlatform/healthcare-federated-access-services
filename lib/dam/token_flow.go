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
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/adapter"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh"

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1"
)

func extractBearerToken(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	if len(auth) == 0 {
		return "", fmt.Errorf("bearer token not found")
	}

	parts := strings.Split(auth, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", fmt.Errorf("token is not a bearer token")
	}

	return parts[1], nil
}

func extractAccessToken(r *http.Request) (string, error) {
	tok, err := extractBearerToken(r)
	if err == nil {
		return tok, nil
	}
	// TODO: access_token should not pass vai query.
	tok = r.URL.Query().Get("access_token")
	if len(tok) > 0 {
		return tok, nil
	}

	return "", fmt.Errorf("access token not found")
}

func extractAuthCode(r *http.Request) (string, error) {
	code := common.GetParam(r, "code")
	if len(code) != 0 {
		return code, nil
	}
	return "", fmt.Errorf("auth code not found")
}

func extractTTL(r *http.Request) (time.Duration, error) {
	str := r.URL.Query().Get("ttl")
	if len(str) == 0 {
		return defaultTTL, nil
	}

	ttl, err := common.ParseDuration(str, defaultTTL)
	if err != nil {
		return 0, fmt.Errorf("TTL parameter %q format error: %v", str, err)
	}
	if ttl == 0 {
		return defaultTTL, nil
	}
	if ttl < 0 || ttl > maxTTL {
		return 0, fmt.Errorf("TTL parameter %q out of range: must be positive and not exceed %s", str, maxTTLStr)
	}
	return ttl, nil
}

func responseKeyFile(r *http.Request) bool {
	return common.GetParam(r, "response_type") == "key-file-type"
}

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

	ttl, err := extractTTL(r)
	if err != nil {
		common.HandleError(http.StatusBadRequest, err, w)
		return
	}

	clientID := getClientID(r)
	status, err = s.checkAuthorization(id, ttl, name, viewName, grantRole, cfg, clientID, nil)
	if err != nil {
		common.HandleError(status, err, w)
		return
	}

	keyFile := responseKeyFile(r)

	resp, status, err := s.generateResourceToken(clientID, name, viewName, grantRole, ttl, keyFile, id, r, cfg, res, view)
	if err != nil {
		common.HandleError(status, err, w)
		return
	}

	if keyFile {
		common.SendJSONResponse(resp.Token, w)
		return
	}
	common.SendResponse(resp, w)
}

func (s *Service) generateResourceToken(clientID, resourceName, viewName, role string, ttl time.Duration, useKeyFile bool, id *ga4gh.Identity, r *http.Request, cfg *pb.DamConfig, res *pb.Resource, view *pb.View) (*pb.GetTokenResponse, int, error) {
	sRole, err := adapter.ResolveServiceRole(role, view, res, cfg)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	if !viewHasRole(view, role) {
		return nil, http.StatusBadRequest, fmt.Errorf("role %q is not defined on resource %q view %q", role, resourceName, viewName)
	}
	st, ok := cfg.ServiceTemplates[view.ServiceTemplate]
	if !ok {
		return nil, http.StatusInternalServerError, fmt.Errorf("view %q service template %q is not defined", viewName, view.ServiceTemplate)
	}
	adapt := s.adapters.ByName[st.TargetAdapter]
	var aggregates []*adapter.AggregateView
	if adapt.IsAggregator() {
		aggregates, err = s.resolveAggregates(res, view, cfg)
		if err != nil {
			return nil, http.StatusInternalServerError, err
		}
	}
	tokenFormat := ""
	if useKeyFile {
		tokenFormat = "application/json"
	}
	adapterAction := &adapter.Action{
		Aggregates:      aggregates,
		Identity:        id,
		Issuer:          getIssuerString(r),
		ClientID:        clientID,
		Config:          cfg,
		GrantRole:       role,
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
		return nil, http.StatusServiceUnavailable, err
	}

	if !useKeyFile {
		return &pb.GetTokenResponse{
			Name:    resourceName,
			View:    s.makeView(viewName, view, res, cfg),
			Account: result.Account,
			Token:   result.Token,
			Ttl:     common.TtlString(ttl),
		}, http.StatusOK, nil
	}

	if common.IsJSON(result.TokenFormat) {
		return &pb.GetTokenResponse{Token: result.Token}, http.StatusOK, nil
	}
	return nil, http.StatusBadRequest, fmt.Errorf("adapter cannot create key file format")
}
