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
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/golang/protobuf/proto" /* copybara-comment */
	"github.com/gorilla/mux" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/persona" /* copybara-comment: persona */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/translator" /* copybara-comment: translator */

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
)

// GetResources implements the GetResources RPC method.
func (s *Service) GetResources(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, err)
		return
	}
	resMap := make(map[string]*pb.Resource, 0)
	for k, v := range cfg.Resources {
		resMap[k] = makeResource(k, v, cfg, s.hidePolicyBasis, s.adapters)
	}

	resp := pb.GetResourcesResponse{
		Resources: resMap,
	}
	httputil.WriteProtoResp(w, proto.Message(&resp))
}

// GetResource implements the corresponding endpoint in the REST API.
func (s *Service) GetResource(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, err)
		return
	}
	name := getName(r)
	if err := checkName(name); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, err)
		return
	}
	res, ok := cfg.Resources[name]
	if !ok {
		httputil.WriteError(w, http.StatusNotFound, fmt.Errorf("resource %q not found", name))
		return
	}
	resp := pb.GetResourceResponse{
		Resource: makeResource(name, res, cfg, s.hidePolicyBasis, s.adapters),
		Access:   s.makeAccessList(nil, []string{name}, nil, nil, cfg, r),
	}
	httputil.WriteProtoResp(w, proto.Message(&resp))
}

// GetFlatViews implements the corresponding REST API endpoint.
func (s *Service) GetFlatViews(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, err)
		return
	}
	viewMap := make(map[string]*pb.GetFlatViewsResponse_FlatView, 0)
	for resname, res := range cfg.Resources {
		for vname, view := range res.Views {
			v := makeView(vname, view, res, cfg, s.hidePolicyBasis, s.adapters)
			st, ok := cfg.ServiceTemplates[v.ServiceTemplate]
			if !ok {
				httputil.WriteError(w, http.StatusInternalServerError, fmt.Errorf("resource %q view %q service template %q is undefined", resname, vname, v.ServiceTemplate))
				return
			}
			desc, ok := s.adapters.Descriptors[st.TargetAdapter]
			if !ok {
				httputil.WriteError(w, http.StatusInternalServerError, fmt.Errorf("resource %q view %q service template %q target adapter %q is undefined", resname, vname, v.ServiceTemplate, st.TargetAdapter))
				return
			}
			for rolename := range v.AccessRoles {
				var roleCat []string
				if sr := st.ServiceRoles[rolename]; sr != nil {
					roleCat = sr.DamRoleCategories
					sort.Strings(roleCat)
				}
				for interfaceName, iface := range v.ComputedInterfaces {
					for _, interfaceURI := range iface.Uri {
						if len(v.ContentTypes) == 0 {
							v.ContentTypes = []string{"*"}
						}
						for _, mime := range v.ContentTypes {
							key := res.Umbrella + "/" + resname + "/" + vname + "/" + rolename + "/" + interfaceName + "/" + mime
							path := strings.Replace(r.URL.Path, "/flatViews", "/resources/"+resname+"/views/"+vname+"/roles/"+rolename, -1)
							viewMap[key] = &pb.GetFlatViewsResponse_FlatView{
								ResourcePath:    path,
								Umbrella:        resname,
								ResourceName:    resname,
								ViewName:        vname,
								RoleName:        rolename,
								InterfaceName:   interfaceName,
								InterfaceUri:    interfaceURI,
								ContentType:     mime,
								Version:         v.Version,
								Topic:           v.Topic,
								Partition:       v.Partition,
								Fidelity:        v.Fidelity,
								GeoLocation:     v.GeoLocation,
								TargetAdapter:   st.TargetAdapter,
								Platform:        desc.Platform,
								PlatformService: st.ItemFormat,
								MaxTokenTtl:     res.MaxTokenTtl,
								ResourceUi:      res.Ui,
								ViewUi:          v.Ui,
								RoleUi:          st.Ui,
								RoleCategories:  roleCat,
							}
						}
					}
				}
			}
		}
	}

	resp := pb.GetFlatViewsResponse{
		Views: viewMap,
	}
	httputil.WriteProtoResp(w, proto.Message(&resp))
}

// GetViews implements the corresponding endpoint in the REST API.
func (s *Service) GetViews(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, err)
		return
	}
	name := getName(r)
	if err := checkName(name); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, err)
		return
	}
	res, ok := cfg.Resources[name]
	if !ok {
		httputil.WriteError(w, http.StatusNotFound, fmt.Errorf("resource %q not found", name))
		return
	}
	out := make(map[string]*pb.View, 0)
	for k, v := range res.Views {
		out[k] = makeView(k, v, res, cfg, s.hidePolicyBasis, s.adapters)
	}
	resp := pb.GetViewsResponse{
		Views:  out,
		Access: s.makeAccessList(nil, []string{name}, nil, nil, cfg, r),
	}
	httputil.WriteProtoResp(w, proto.Message(&resp))
}

// GetView implements the corresponding endpoint in the REST API.
func (s *Service) GetView(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, err)
		return
	}
	name := getName(r)
	if err := checkName(name); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, err)
		return
	}
	res, ok := cfg.Resources[name]
	if !ok {
		httputil.WriteError(w, http.StatusNotFound, fmt.Errorf("resource %q not found", name))
		return
	}
	viewName := mux.Vars(r)["view"]
	if err := checkName(viewName); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, err)
		return
	}
	view, ok := res.Views[viewName]
	if !ok {
		httputil.WriteError(w, http.StatusNotFound, fmt.Errorf("resource %q view %q not found", name, viewName))
		return
	}
	resp := pb.GetViewResponse{
		View:   makeView(viewName, view, res, cfg, s.hidePolicyBasis, s.adapters),
		Access: s.makeAccessList(nil, []string{name}, []string{viewName}, nil, cfg, r),
	}
	httputil.WriteProtoResp(w, proto.Message(&resp))
}

// GetViewRoles implements the corresponding endpoint in the REST API.
func (s *Service) GetViewRoles(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, err)
		return
	}
	name := getName(r)
	if err := checkName(name); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, err)
		return
	}
	res, ok := cfg.Resources[name]
	if !ok {
		httputil.WriteError(w, http.StatusNotFound, fmt.Errorf("resource %q not found", name))
		return
	}
	viewName := mux.Vars(r)["view"]
	if err := checkName(viewName); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, err)
		return
	}
	view, ok := res.Views[viewName]
	if !ok {
		httputil.WriteError(w, http.StatusNotFound, fmt.Errorf("resource %q view %q not found", name, viewName))
		return
	}
	out := makeViewRoles(view, res, cfg, s.hidePolicyBasis, s.adapters)
	resp := pb.GetViewRolesResponse{
		Roles:  out,
		Access: s.makeAccessList(nil, []string{name}, []string{viewName}, nil, cfg, r),
	}
	httputil.WriteProtoResp(w, proto.Message(&resp))
}

// GetViewRole implements the corresponding endpoint in the REST API.
func (s *Service) GetViewRole(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, err)
		return
	}
	name := getName(r)
	if err := checkName(name); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, err)
		return
	}
	res, ok := cfg.Resources[name]
	if !ok {
		httputil.WriteError(w, http.StatusNotFound, fmt.Errorf("resource %q not found", name))
		return
	}
	vars := mux.Vars(r)
	viewName := vars["view"]
	if err := checkName(viewName); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, err)
		return
	}
	view, ok := res.Views[viewName]
	if !ok {
		httputil.WriteError(w, http.StatusNotFound, fmt.Errorf("resource %q view %q not found", name, viewName))
		return
	}
	roleName := vars["role"]
	if err := checkName(roleName); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, err)
		return
	}
	roles := makeViewRoles(view, res, cfg, s.hidePolicyBasis, s.adapters)
	role, ok := roles[roleName]
	if !ok {
		httputil.WriteError(w, http.StatusNotFound, fmt.Errorf("resource %q view %q role %q not found", name, viewName, roleName))
		return
	}
	resp := pb.GetViewRoleResponse{
		Role:   role,
		Access: s.makeAccessList(nil, []string{name}, []string{viewName}, []string{roleName}, cfg, r),
	}
	httputil.WriteProtoResp(w, proto.Message(&resp))
}

// GetTargetAdapters implements the corresponding REST API endpoint.
func (s *Service) GetTargetAdapters(w http.ResponseWriter, r *http.Request) {
	out := &pb.TargetAdaptersResponse{
		TargetAdapters: s.adapters.Descriptors,
	}
	httputil.WriteProtoResp(w, out)
}

func (s *Service) getIssuerTranslator(ctx context.Context, issuer string, cfg *pb.DamConfig, secrets *pb.DamSecrets, tx storage.Tx) (translator.Translator, error) {
	v, ok := s.translators.Load(issuer)
	var t translator.Translator
	var err error
	if ok {
		t, ok = v.(translator.Translator)
		if !ok {
			return nil, fmt.Errorf("passport issuer %q with wrong type", issuer)
		}
		return t, nil
	}
	var cfgTpi *pb.TrustedPassportIssuer
	for _, tpi := range cfg.TrustedPassportIssuers {
		if tpi.Issuer == issuer {
			cfgTpi = tpi
			break
		}
	}
	if cfgTpi == nil {
		return nil, fmt.Errorf("passport issuer not found %q", issuer)
	}

	if secrets == nil {
		secrets, err = s.loadSecrets(tx)
		if err != nil {
			return nil, fmt.Errorf("load secrets: %q", err)
		}
	}

	t, err = s.createIssuerTranslator(ctx, cfgTpi, secrets)
	if err != nil {
		return nil, fmt.Errorf("failed to create translator for issuer %q: %v", issuer, err)
	}
	s.translators.Store(issuer, t)
	return t, err
}

func (s *Service) createIssuerTranslator(ctx context.Context, cfgTpi *pb.TrustedPassportIssuer, secrets *pb.DamSecrets) (translator.Translator, error) {
	return translator.CreateTranslator(ctx, cfgTpi.Issuer, cfgTpi.TranslateUsing, cfgTpi.ClientId, secrets.PublicTokenKeys[cfgTpi.Issuer], "", "")
}

// GetPassportTranslators implements the corresponding REST API endpoint.
func (s *Service) GetPassportTranslators(w http.ResponseWriter, r *http.Request) {
	out := translator.GetPassportTranslators()
	httputil.WriteProtoResp(w, out)
}

// GetDamRoleCategories implements the corresponding REST API method.
func (s *Service) GetDamRoleCategories(w http.ResponseWriter, r *http.Request) {
	out := &pb.DamRoleCategoriesResponse{
		DamRoleCategories: s.roleCategories,
	}
	httputil.WriteProtoResp(w, out)
}

// GetTestPersonas implements the corresponding REST API method.
func (s *Service) GetTestPersonas(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, err)
		return
	}
	out := &pb.GetTestPersonasResponse{
		Personas:       cfg.TestPersonas,
		StandardClaims: persona.StandardClaims,
	}
	httputil.WriteProtoResp(w, out)
}
