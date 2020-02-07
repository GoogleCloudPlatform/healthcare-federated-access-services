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
		httputil.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	resMap := make(map[string]*pb.Resource, 0)
	for k, v := range cfg.Resources {
		resMap[k] = s.makeResource(k, v, cfg)
	}

	resp := pb.GetResourcesResponse{
		Resources: resMap,
	}
	httputil.SendResponse(proto.Message(&resp), w)
}

// GetResource implements the corresponding endpoint in the REST API.
func (s *Service) GetResource(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		httputil.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	name := getName(r)
	if err := checkName(name); err != nil {
		httputil.HandleError(http.StatusBadRequest, err, w)
		return
	}
	res, ok := cfg.Resources[name]
	if !ok {
		httputil.HandleError(http.StatusNotFound, fmt.Errorf("resource %q not found", name), w)
		return
	}
	resp := pb.GetResourceResponse{
		Resource: s.makeResource(name, res, cfg),
		Access:   s.makeAccessList(nil, []string{name}, nil, nil, cfg, r),
	}
	httputil.SendResponse(proto.Message(&resp), w)
}

// GetFlatViews implements the corresponding REST API endpoint.
func (s *Service) GetFlatViews(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		httputil.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	viewMap := make(map[string]*pb.GetFlatViewsResponse_FlatView, 0)
	for resname, res := range cfg.Resources {
		for vname, view := range res.Views {
			v := s.makeView(vname, view, res, cfg)
			st, ok := cfg.ServiceTemplates[v.ServiceTemplate]
			if !ok {
				httputil.HandleError(http.StatusInternalServerError, fmt.Errorf("resource %q view %q service template %q is undefined", resname, vname, v.ServiceTemplate), w)
				return
			}
			desc, ok := s.adapters.Descriptors[st.TargetAdapter]
			if !ok {
				httputil.HandleError(http.StatusInternalServerError, fmt.Errorf("resource %q view %q service template %q target adapter %q is undefined", resname, vname, v.ServiceTemplate, st.TargetAdapter), w)
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
	httputil.SendResponse(proto.Message(&resp), w)
}

// GetViews implements the corresponding endpoint in the REST API.
func (s *Service) GetViews(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		httputil.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	name := getName(r)
	if err := checkName(name); err != nil {
		httputil.HandleError(http.StatusBadRequest, err, w)
		return
	}
	res, ok := cfg.Resources[name]
	if !ok {
		httputil.HandleError(http.StatusNotFound, fmt.Errorf("resource %q not found", name), w)
		return
	}
	out := make(map[string]*pb.View, 0)
	for k, v := range res.Views {
		out[k] = s.makeView(k, v, res, cfg)
	}
	resp := pb.GetViewsResponse{
		Views:  out,
		Access: s.makeAccessList(nil, []string{name}, nil, nil, cfg, r),
	}
	httputil.SendResponse(proto.Message(&resp), w)
}

// GetView implements the corresponding endpoint in the REST API.
func (s *Service) GetView(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		httputil.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	name := getName(r)
	if err := checkName(name); err != nil {
		httputil.HandleError(http.StatusBadRequest, err, w)
		return
	}
	res, ok := cfg.Resources[name]
	if !ok {
		httputil.HandleError(http.StatusNotFound, fmt.Errorf("resource %q not found", name), w)
		return
	}
	viewName := mux.Vars(r)["view"]
	if err := checkName(viewName); err != nil {
		httputil.HandleError(http.StatusBadRequest, err, w)
		return
	}
	view, ok := res.Views[viewName]
	if !ok {
		httputil.HandleError(http.StatusNotFound, fmt.Errorf("resource %q view %q not found", name, viewName), w)
		return
	}
	resp := pb.GetViewResponse{
		View:   s.makeView(viewName, view, res, cfg),
		Access: s.makeAccessList(nil, []string{name}, []string{viewName}, nil, cfg, r),
	}
	httputil.SendResponse(proto.Message(&resp), w)
}

// GetViewRoles implements the corresponding endpoint in the REST API.
func (s *Service) GetViewRoles(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		httputil.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	name := getName(r)
	if err := checkName(name); err != nil {
		httputil.HandleError(http.StatusBadRequest, err, w)
		return
	}
	res, ok := cfg.Resources[name]
	if !ok {
		httputil.HandleError(http.StatusNotFound, fmt.Errorf("resource %q not found", name), w)
		return
	}
	viewName := mux.Vars(r)["view"]
	if err := checkName(viewName); err != nil {
		httputil.HandleError(http.StatusBadRequest, err, w)
		return
	}
	view, ok := res.Views[viewName]
	if !ok {
		httputil.HandleError(http.StatusNotFound, fmt.Errorf("resource %q view %q not found", name, viewName), w)
		return
	}
	out := s.makeViewRoles(view, res, cfg)
	resp := pb.GetViewRolesResponse{
		Roles:  out,
		Access: s.makeAccessList(nil, []string{name}, []string{viewName}, nil, cfg, r),
	}
	httputil.SendResponse(proto.Message(&resp), w)
}

// GetViewRole implements the corresponding endpoint in the REST API.
func (s *Service) GetViewRole(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		httputil.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	name := getName(r)
	if err := checkName(name); err != nil {
		httputil.HandleError(http.StatusBadRequest, err, w)
		return
	}
	res, ok := cfg.Resources[name]
	if !ok {
		httputil.HandleError(http.StatusNotFound, fmt.Errorf("resource %q not found", name), w)
		return
	}
	vars := mux.Vars(r)
	viewName := vars["view"]
	if err := checkName(viewName); err != nil {
		httputil.HandleError(http.StatusBadRequest, err, w)
		return
	}
	view, ok := res.Views[viewName]
	if !ok {
		httputil.HandleError(http.StatusNotFound, fmt.Errorf("resource %q view %q not found", name, viewName), w)
		return
	}
	roleName := vars["role"]
	if err := checkName(roleName); err != nil {
		httputil.HandleError(http.StatusBadRequest, err, w)
		return
	}
	roles := s.makeViewRoles(view, res, cfg)
	role, ok := roles[roleName]
	if !ok {
		httputil.HandleError(http.StatusNotFound, fmt.Errorf("resource %q view %q role %q not found", name, viewName, roleName), w)
		return
	}
	resp := pb.GetViewRoleResponse{
		Role:   role,
		Access: s.makeAccessList(nil, []string{name}, []string{viewName}, []string{roleName}, cfg, r),
	}
	httputil.SendResponse(proto.Message(&resp), w)
}

// GetTargetAdapters implements the corresponding REST API endpoint.
func (s *Service) GetTargetAdapters(w http.ResponseWriter, r *http.Request) {
	out := &pb.TargetAdaptersResponse{
		TargetAdapters: s.adapters.Descriptors,
	}
	httputil.SendResponse(out, w)
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
	httputil.SendResponse(out, w)
}

// GetDamRoleCategories implements the corresponding REST API method.
func (s *Service) GetDamRoleCategories(w http.ResponseWriter, r *http.Request) {
	out := &pb.DamRoleCategoriesResponse{
		DamRoleCategories: s.roleCategories,
	}
	httputil.SendResponse(out, w)
}

// GetTestPersonas implements the corresponding REST API method.
func (s *Service) GetTestPersonas(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		httputil.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	out := &pb.GetTestPersonasResponse{
		Personas:       cfg.TestPersonas,
		StandardClaims: persona.StandardClaims,
	}
	httputil.SendResponse(out, w)
}
