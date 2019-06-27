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
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
	"github.com/gorilla/mux"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/adapter"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/clouds"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/common"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/playground"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/storage"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/translator"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/validator"

	pb "google3/third_party/hcls_federated_access/dam/api/v1/go_proto"
)

const (
	version       = "v1alpha"
	realmVariable = "{realm}"

	basePath     = "/dam"
	methodPrefix = basePath + "/" + version + "/" + realmVariable + "/"

	infoPath              = basePath
	realmPath             = basePath + "/" + version + "/{realm}"
	resourcesPath         = methodPrefix + "resources"
	resourcePath          = methodPrefix + "resources/{name}"
	flatViewsPath         = methodPrefix + "flatViews"
	viewsPath             = methodPrefix + "resources/{name}/views"
	viewPath              = methodPrefix + "resources/{name}/views/{view}"
	rolesPath             = methodPrefix + "resources/{name}/views/{view}/roles"
	rolePath              = methodPrefix + "resources/{name}/views/{view}/roles/{role}"
	viewTokenPath         = methodPrefix + "resources/{name}/views/{view}/token"
	roleTokenPath         = methodPrefix + "resources/{name}/views/{view}/roles/{role}/token"
	testPath              = methodPrefix + "tests"
	clientSecretPath      = methodPrefix + "clientSecret"
	adaptersPath          = methodPrefix + "targetAdapters"
	translatorsPath       = methodPrefix + "passportTranslators"
	damRoleCategoriesPath = methodPrefix + "damRoleCategories"
	testPersonasPath      = methodPrefix + "testPersonas"
	processesPath         = methodPrefix + "processes"
	processPath           = methodPrefix + "processes/{name}"

	configPath                      = methodPrefix + "config"
	configResourcePath              = configPath + "/resources/{name}"
	configViewPath                  = configPath + "/resources/{resource}/views/{name}"
	configTrustedPassportIssuerPath = configPath + "/trustedPassportIssuers/{name}"
	configTrustedSourcePath         = configPath + "/trustedSources/{name}"
	configPolicyPath                = configPath + "/policies/{name}"
	configOptionsPath               = configPath + "/options"
	configClaimDefPath              = configPath + "/claimDefinitions/{name}"
	configServiceTemplatePath       = configPath + "/serviceTemplates/{name}"
	configClientPath                = configPath + "/clients/{name}"
	configTestPersonasPath          = configPath + "/testPersonas"
	configTestPersonaPath           = configPath + "/testPersonas/{name}"
	configHistoryPath               = configPath + "/history"
	configHistoryRevisionPath       = configHistoryPath + "/{name}"
	configResetPath                 = configPath + "/reset"
	configClientSecretPath          = configPath + "/clientSecret/{name}"

	maxNameLength = 32
	minNameLength = 3
	clientIdLen   = 36

	noClientID          = ""
	noScope             = ""
	defaultPersonaScope = ""
	damStaticService    = "dam-static"
	inheritService      = ""

	requestTTLInNanoFloat64 = ga4gh.ContextKey("requested_ttl")
)

var (
	ttlRE = regexp.MustCompile(`^[0-9]+[smhdw]$`)

	defaultTTL = 1 * time.Hour
	maxTTL     = 90 * 24 * time.Hour // keep in sync with maxTTLStr
	maxTTLStr  = "90 days"           // keep in sync with maxTTL

	translators = translator.PassportTranslators()
)

type Service struct {
	adapters       *adapter.TargetAdapters
	roleCategories map[string]*pb.RoleCategory
	domainURL      string
	store          storage.Store
	warehouse      clouds.ResourceTokenCreator
	permissions    *common.Permissions
	Handler        *ServiceHandler
	ctx            context.Context
	startTime      int64
	translators    sync.Map
}

type ServiceHandler struct {
	Handler *mux.Router
	s       *Service
}

// NewService create DAM service
// - ctx: pass in http.Client can replace the one used in oidc request
// - domain: domain used to host DAM service
// - store: data storage and configuration storage
// - warehouse: resource token creator service
func NewService(ctx context.Context, domain string, store storage.Store, warehouse clouds.ResourceTokenCreator) *Service {
	fs := getFileStore(store, damStaticService)
	var roleCat pb.DamRoleCategoriesResponse
	if err := fs.Read("role", storage.DefaultRealm, storage.DefaultUser, "en", storage.LatestRev, &roleCat); err != nil {
		log.Fatalf("cannot load role categories: %v", err)
	}
	perms, err := common.LoadPermissions(store)
	if err != nil {
		log.Fatalf("cannot load permissions: %v", err)
	}

	sh := &ServiceHandler{}
	s := &Service{
		roleCategories: roleCat.DamRoleCategories,
		domainURL:      domain,
		store:          store,
		warehouse:      warehouse,
		permissions:    perms,
		Handler:        sh,
		ctx:            ctx,
		startTime:      time.Now().Unix(),
	}

	secrets, err := s.loadSecrets(nil)
	if err != nil {
		if isAutoReset() {
			if impErr := s.importFiles(); impErr == nil {
				secrets, err = s.loadSecrets(nil)
			}
		}
		if err != nil {
			log.Fatalf("cannot load client secrets: %v", err)
		}
	}
	adapters, err := adapter.CreateAdapters(fs, warehouse, secrets)
	if err != nil {
		log.Fatalf("cannot load adapters: %v", err)
	}
	s.adapters = adapters
	if err := s.importFiles(); err != nil {
		log.Fatalf("cannot initialize storage: %v", err)
	}
	cfg, err := s.loadConfig(nil, storage.DefaultRealm)
	if err != nil {
		log.Fatalf("cannot load config: %v", err)
	}
	if err := s.CheckIntegrity(cfg); err != nil {
		log.Fatalf("config integrity error: %v", err)
	}
	if tests := s.runTests(cfg, nil); hasTestError(tests) {
		log.Fatalf("run tests error: %v; results: %v; modification: <%v>", tests.Error, tests.TestResults, tests.Modification)
	}

	for name, cfgTpi := range cfg.TrustedPassportIssuers {
		_, err = s.getIssuerTranslator(s.ctx, cfgTpi.Issuer, cfg, secrets, nil)
		if err != nil {
			log.Printf("failed to create translator for issuer %q: %v", name, err)
		}
	}

	sh.s = s
	sh.Handler = s.buildHandlerMux()
	return s
}

func getClientID(r *http.Request) string {
	cid := r.URL.Query().Get("client_id")
	if len(cid) > 0 {
		return cid
	}
	return r.URL.Query().Get("clientId")
}

func getClientSecret(r *http.Request) string {
	cs := r.URL.Query().Get("client_secret")
	if len(cs) > 0 {
		return cs
	}
	return r.URL.Query().Get("clientSecret")
}

func getRealm(r *http.Request) string {
	if realm, ok := mux.Vars(r)["realm"]; ok && len(realm) > 0 {
		return realm
	}
	return storage.DefaultRealm
}

func getName(r *http.Request) string {
	if name, ok := mux.Vars(r)["name"]; ok && len(name) > 0 {
		return name
	}
	return ""
}

func (s *Service) handlerSetup(tx storage.Tx, isAdmin bool, r *http.Request, scope string, item proto.Message) (*pb.DamConfig, *ga4gh.Identity, int, error) {
	if item != nil {
		if err := jsonpb.Unmarshal(r.Body, item); err != nil && err != io.EOF {
			return nil, nil, http.StatusBadRequest, err
		}
	}
	cfg, err := s.loadConfig(tx, getRealm(r))
	if err != nil {
		return nil, nil, http.StatusServiceUnavailable, err
	}
	id, status, err := s.getPassportIdentity(cfg, tx, r)
	if err != nil {
		return nil, nil, status, err
	}
	if isAdmin {
		if status, err := s.permissions.CheckAdmin(id); err != nil {
			return nil, nil, status, err
		}
	}
	return cfg, id, status, err
}

func (sh *ServiceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "OPTIONS" {
		common.AddCorsHeaders(w)
		w.WriteHeader(http.StatusOK)
		return
	}
	r.ParseForm()
	if r.URL.Path == infoPath {
		sh.Handler.ServeHTTP(w, r)
		return
	}
	cid := getClientID(r)
	if len(cid) == 0 {
		http.Error(w, "authorization requires a client ID", http.StatusUnauthorized)
		return
	}
	cs := getClientSecret(r)
	if len(cs) == 0 {
		// Allow a request to allocate a client secret to proceed.
		parts := strings.Split(r.URL.Path, "/")
		// Path starts with a "/", so first part is always empty.
		if len(parts) > 3 {
			parts[3] = realmVariable
		}
		path := strings.Join(parts, "/")
		if strings.HasPrefix(path, clientSecretPath) {
			sh.Handler.ServeHTTP(w, r)
			return
		}
		http.Error(w, "authorization requires a client secret", http.StatusUnauthorized)
		return
	}

	secrets, err := sh.s.loadSecrets(nil)
	if err != nil {
		http.Error(w, "configuration unavailable", http.StatusServiceUnavailable)
		return
	}

	if secret, ok := secrets.ClientSecrets[cid]; !ok || secret != cs {
		http.Error(w, "unauthorized client", http.StatusUnauthorized)
		return
	}
	sh.Handler.ServeHTTP(w, r)
}

func (s *Service) buildHandlerMux() *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc(infoPath, s.GetInfo)
	r.HandleFunc(resourcesPath, s.GetResources)
	r.HandleFunc(resourcePath, s.GetResource)
	r.HandleFunc(viewsPath, s.GetViews)
	r.HandleFunc(flatViewsPath, s.GetFlatViews)
	r.HandleFunc(viewPath, s.GetView)
	r.HandleFunc(rolesPath, s.GetViewRoles)
	r.HandleFunc(rolePath, s.GetViewRole)
	r.HandleFunc(viewTokenPath, s.GetResourceToken)
	r.HandleFunc(roleTokenPath, s.GetResourceToken)
	r.HandleFunc(testPath, s.GetTestResults)
	r.HandleFunc(clientSecretPath, s.ClientSecret)
	r.HandleFunc(adaptersPath, s.GetTargetAdapters)
	r.HandleFunc(translatorsPath, s.GetPassportTranslators)
	r.HandleFunc(damRoleCategoriesPath, s.GetDamRoleCategories)
	r.HandleFunc(testPersonasPath, s.GetTestPersonas)
	r.HandleFunc(realmPath, common.MakeHandler(s, s.realmFactory()))
	r.HandleFunc(processesPath, common.MakeHandler(s, s.processesFactory()))
	r.HandleFunc(processPath, common.MakeHandler(s, s.processFactory()))

	r.HandleFunc(configHistoryPath, s.ConfigHistory)
	r.HandleFunc(configHistoryRevisionPath, s.ConfigHistoryRevision)
	r.HandleFunc(configResetPath, s.ConfigReset)
	r.HandleFunc(configClientSecretPath, s.ConfigClientSecret)
	r.HandleFunc(configTestPersonasPath, s.ConfigTestPersonas)

	r.HandleFunc(configPath, common.MakeHandler(s, s.configFactory()))
	r.HandleFunc(configOptionsPath, common.MakeHandler(s, s.configOptionsFactory()))
	r.HandleFunc(configResourcePath, common.MakeHandler(s, s.configResourceFactory()))
	r.HandleFunc(configViewPath, common.MakeHandler(s, s.configViewFactory()))
	r.HandleFunc(configTrustedPassportIssuerPath, common.MakeHandler(s, s.configIssuerFactory()))
	r.HandleFunc(configTrustedSourcePath, common.MakeHandler(s, s.configSourceFactory()))
	r.HandleFunc(configPolicyPath, common.MakeHandler(s, s.configPolicyFactory()))
	r.HandleFunc(configClaimDefPath, common.MakeHandler(s, s.configClaimDefinitionFactory()))
	r.HandleFunc(configServiceTemplatePath, common.MakeHandler(s, s.configServiceTemplateFactory()))
	r.HandleFunc(configTestPersonaPath, common.MakeHandler(s, s.configPersonaFactory()))
	r.HandleFunc(configClientPath, common.MakeHandler(s, s.configClientFactory()))

	return r
}

func checkName(name string) error {
	return common.CheckName("name", name, nil)
}

func (s *Service) getPassportIdentity(cfg *pb.DamConfig, tx storage.Tx, r *http.Request) (*ga4gh.Identity, int, error) {
	// TODO: remove the persona query parameter feature.
	pname := r.URL.Query().Get("persona")
	if len(pname) > 0 {
		p, ok := cfg.TestPersonas[pname]
		if !ok || p == nil {
			return nil, http.StatusUnauthorized, fmt.Errorf("unauthorized")
		}
		id, err := playground.PersonaToIdentity(pname, p, defaultPersonaScope)
		if err != nil {
			return nil, http.StatusInternalServerError, err
		}
		return id, http.StatusOK, nil
	}

	auth := r.Header.Get("Authorization")
	paramTok := r.URL.Query().Get("access_token")
	if len(paramTok) == 0 && len(auth) > 0 {
		paramTok = auth
	} else {
		paramTok = "bearer " + paramTok
	}

	parts := strings.SplitN(paramTok, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return nil, http.StatusUnauthorized, fmt.Errorf("authorization requires a bearer token")
	}

	tok := parts[1]
	id, err := common.ConvertTokenToIdentityUnsafe(tok)
	if err != nil {
		return nil, http.StatusUnauthorized, fmt.Errorf("inspecting token: %v", err)
	}

	iss := id.Issuer
	t, err := s.getIssuerTranslator(s.ctx, iss, cfg, nil, tx)
	if err != nil {
		return nil, http.StatusUnauthorized, err
	}

	id, err = t.TranslateToken(s.ctx, tok)
	if err != nil {
		return nil, http.StatusUnauthorized, fmt.Errorf("translating token from issuer %q: %v", iss, err)
	}
	if common.HasUserinfoClaims(id.UserinfoClaims) {
		id, err = translator.FetchUserinfoClaims(s.ctx, tok, id, t)
		if err != nil {
			return nil, http.StatusUnauthorized, fmt.Errorf("fetching user info from issuer %q: %v", iss, err)
		}
	}

	// DAM will only accept tokens designated for use by the requestor's client ID.
	if len(id.AuthorizedParty) == 0 || id.AuthorizedParty != getClientID(r) {
		return nil, http.StatusUnauthorized, fmt.Errorf("mismatched authorized party")
	}
	if err := id.Valid(); err != nil {
		return nil, http.StatusUnauthorized, err
	}

	return id, http.StatusOK, nil
}

func (s *Service) testPersona(personaName string, resources []string, cfg *pb.DamConfig, vm map[string]*validator.Policy) (string, map[string]*pb.AccessList, error) {
	persona := cfg.TestPersonas[personaName]
	id, err := playground.PersonaToIdentity(personaName, persona, defaultPersonaScope)
	if err != nil {
		return "INVALID", nil, err
	}
	state, got, err := s.resolveAccessList(id, resources, nil, nil, cfg, vm)
	if err != nil {
		return state, got, err
	}
	if reflect.DeepEqual(persona.Resources, got) || (len(persona.Resources) == 0 && len(got) == 0) {
		return "PASSED", got, nil
	}
	return "FAILED", got, fmt.Errorf("access does not match expectations")
}

func (s *Service) resolveAccessList(id *ga4gh.Identity, resources, views, roles []string, cfg *pb.DamConfig, vm map[string]*validator.Policy) (string, map[string]*pb.AccessList, error) {
	got := make(map[string]*pb.AccessList)
	for _, rn := range resources {
		r, ok := cfg.Resources[rn]
		if !ok {
			return "FAILED", got, fmt.Errorf("resource %q not found", rn)
		}
		got[rn] = &pb.AccessList{Access: []string{}}
		for vn, v := range r.Views {
			if len(views) > 0 && !common.ListContains(views, vn) {
				continue
			}
			if len(v.AccessRoles) == 0 {
				return "INVALID", nil, fmt.Errorf("resource %q view %q has no roles defined", rn, vn)
			}
			for rname := range v.AccessRoles {
				if len(roles) > 0 && !common.ListContains(roles, rname) {
					continue
				}
				if _, err := s.checkAuthorization(id, 0, rn, vn, rname, cfg, noClientID, vm); err != nil {
					continue
				}
				got[rn].Access = mergeLists(got[rn].Access, []string{vn + "/" + rname})
			}
		}
		sort.Strings(got[rn].Access)
		if len(got[rn].Access) == 0 {
			delete(got, rn)
		}
	}
	return "OK", got, nil
}

func (s *Service) makeAccessList(id *ga4gh.Identity, resources, views, roles []string, cfg *pb.DamConfig, r *http.Request) []string {
	out := []string{}
	vm, err := s.buildValidatorMap(cfg)
	if err != nil {
		return out
	}
	if id == nil {
		id, _, err = s.getPassportIdentity(cfg, nil, r)
		if err != nil {
			return out
		}
	}
	_, got, err := s.resolveAccessList(id, resources, views, roles, cfg, vm)
	if err != nil {
		return out
	}
	for _, v := range got {
		out = mergeLists(out, v.Access)
	}
	return out
}

func (s *Service) checkAuthorization(id *ga4gh.Identity, ttl time.Duration, resourceName, viewName, roleName string, cfg *pb.DamConfig, client string, vm map[string]*validator.Policy) (int, error) {
	if err := s.checkTrustedIssuer(id.Issuer, cfg); err != nil {
		return http.StatusForbidden, err
	}
	srcRes, ok := cfg.Resources[resourceName]
	if !ok {
		return http.StatusNotFound, fmt.Errorf("resource %q not found", resourceName)
	}
	srcView, ok := srcRes.Views[viewName]
	if !ok {
		return http.StatusNotFound, fmt.Errorf("resource %q view %q not found", resourceName, viewName)
	}
	entries, err := s.resolveAggregates(srcRes, srcView, cfg)
	if err != nil {
		return http.StatusForbidden, err
	}
	if vm == nil {
		var err error
		vm, err = s.buildValidatorMap(cfg)
		if err != nil {
			return http.StatusForbidden, err
		}
	}
	active := false
	for _, entry := range entries {
		view := entry.View
		res := entry.Res
		vRole, ok := view.AccessRoles[roleName]
		if !ok {
			return http.StatusForbidden, fmt.Errorf("unauthorized for resource %q view %q role %q (role not available on this view)", resourceName, viewName, roleName)
		}
		_, err := adapter.ResolveServiceRole(roleName, view, res, cfg)
		if err != nil {
			return http.StatusForbidden, fmt.Errorf("unauthorized for resource %q view %q role %q (cannot resolve service role)", resourceName, viewName, roleName)
		}
		if len(vRole.Policies) == 0 {
			return http.StatusForbidden, fmt.Errorf("unauthorized for resource %q view %q role %q (no policy defined for this view's role)", resourceName, viewName, roleName)
		}
		ctxWithTTL := context.WithValue(s.ctx, requestTTLInNanoFloat64, float64(ttl.Nanoseconds())/1e9)
		for _, policy := range vRole.Policies {
			v, ok := vm[policy]
			if !ok {
				return http.StatusInternalServerError, fmt.Errorf("cannot enforce policies for resource %q view %q role %q", resourceName, viewName, roleName)
			}
			ok, err := v.Validate(ctxWithTTL, id)
			if err != nil {
				// TODO: strip internal error
				return http.StatusInternalServerError, fmt.Errorf("cannot validate identity: %v", err)
			}
			if !ok {
				return http.StatusForbidden, fmt.Errorf("unauthorized for resource %q view %q role %q (policy requirements failed)", resourceName, viewName, roleName)
			}
			active = true
		}
	}
	if !active {
		return http.StatusForbidden, fmt.Errorf("unauthorized for resource %q view %q role %q (role not enabled)", resourceName, viewName, roleName)
	}
	return http.StatusOK, nil
}

func (s *Service) resolveAggregates(srcRes *pb.Resource, srcView *pb.View, cfg *pb.DamConfig) ([]*adapter.AggregateView, error) {
	out := []*adapter.AggregateView{}
	st, ok := cfg.ServiceTemplates[srcView.ServiceTemplate]
	if !ok {
		return nil, fmt.Errorf("service template %q not found", srcView.ServiceTemplate)
	}
	if !s.isAggregate(st.TargetAdapter) {
		out = append(out, &adapter.AggregateView{
			Index: 0,
			Res:   srcRes,
			View:  srcView,
		})
		return out, nil
	}
	targetAdapter := ""
	for index, item := range srcView.Items {
		vars, err := adapter.GetItemVariables(s.adapters, st.TargetAdapter, st.ItemFormat, item)
		if err != nil {
			return nil, fmt.Errorf("item %d: %v", index+1, err)
		}
		resName := vars["resource"]
		res, ok := cfg.Resources[resName]
		if !ok {
			return nil, fmt.Errorf("item %d: resource not found", index+1)
		}
		viewName := vars["view"]
		view, ok := res.Views[viewName]
		if !ok {
			return nil, fmt.Errorf("item %d: view not found within the specified resource", index+1)
		}
		vst, ok := cfg.ServiceTemplates[view.ServiceTemplate]
		if !ok {
			return nil, fmt.Errorf("item %d: service template %q on the view is undefined", index+1, view.ServiceTemplate)
		}
		if s.isAggregate(vst.TargetAdapter) {
			return nil, fmt.Errorf("item %d: view uses aggregate service template %q and nesting aggregates is not permitted", index+1, vst.TargetAdapter)
		}
		if targetAdapter == "" {
			targetAdapter = vst.TargetAdapter
		} else if targetAdapter != vst.TargetAdapter {
			return nil, fmt.Errorf("item %d: service template %q uses a different target adapter %q than previous items (%q)", index+1, view.ServiceTemplate, vst.TargetAdapter, targetAdapter)
		}
		out = append(out, &adapter.AggregateView{
			Index: index,
			Res:   res,
			View:  view,
		})
	}
	return out, nil
}

func (s *Service) isAggregate(targetAdapter string) bool {
	desc, ok := s.adapters.Descriptors[targetAdapter]
	if !ok {
		return false
	}
	return desc.Properties.IsAggregate
}

func isHTTPS(in string) bool {
	return strings.HasPrefix(in, "https://") && strings.Contains(in, ".")
}

func isLocalhost(in string) bool {
	url, err := url.Parse(in)
	if err != nil {
		return false
	}
	return url.Hostname() == "localhost"
}

func configRevision(mod *pb.ConfigModification, cfg *pb.DamConfig) error {
	if mod != nil && mod.Revision > 0 && mod.Revision != cfg.Revision {
		return fmt.Errorf("request revision %d is out of date with current config revision %d", mod.Revision, cfg.Revision)
	}
	return nil
}

func (s *Service) GetInfo(w http.ResponseWriter, r *http.Request) {
	out := &pb.GetInfoResponse{
		Name:      "Data Access Manager",
		Versions:  []string{version},
		StartTime: s.startTime,
	}
	realm := common.GetParamOrDefault(r, "realm", storage.DefaultRealm)
	if cfg, err := s.loadConfig(nil, realm); err == nil {
		out.Ui = cfg.Ui
	}
	common.SendResponse(out, w)
}

// GetResources implements the GetResources RPC method.
func (s *Service) GetResources(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request method not supported: %q", r.Method), w)
		return
	}
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	resMap := make(map[string]*pb.Resource, 0)
	for k, v := range cfg.Resources {
		resMap[k] = s.makeResource(k, v, cfg)
	}

	resp := pb.GetResourcesResponse{
		Resources: resMap,
	}
	common.SendResponse(proto.Message(&resp), w)
}

// GetResource implements the corresponding endpoint in the REST API.
func (s *Service) GetResource(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request method not supported: %q", r.Method), w)
		return
	}
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	name := getName(r)
	if err := checkName(name); err != nil {
		common.HandleError(http.StatusBadRequest, err, w)
		return
	}
	res, ok := cfg.Resources[name]
	if !ok {
		common.HandleError(http.StatusNotFound, fmt.Errorf("resource %q not found", name), w)
		return
	}
	resp := pb.GetResourceResponse{
		Resource: s.makeResource(name, res, cfg),
		Access:   s.makeAccessList(nil, []string{name}, nil, nil, cfg, r),
	}
	common.SendResponse(proto.Message(&resp), w)
}

// GetFlatViews implements the corresponding REST API endpoint.
func (s *Service) GetFlatViews(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request method not supported: %q", r.Method), w)
		return
	}
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	viewMap := make(map[string]*pb.GetFlatViewsResponse_FlatView, 0)
	for resname, res := range cfg.Resources {
		for vname, view := range res.Views {
			v := s.makeView(vname, view, res, cfg)
			st, ok := cfg.ServiceTemplates[v.ServiceTemplate]
			if !ok {
				common.HandleError(http.StatusInternalServerError, fmt.Errorf("resource %q view %q service template %q is undefined", resname, vname, v.ServiceTemplate), w)
				return
			}
			desc, ok := s.adapters.Descriptors[st.TargetAdapter]
			if !ok {
				common.HandleError(http.StatusInternalServerError, fmt.Errorf("resource %q view %q service template %q target adapter %q is undefined", resname, vname, v.ServiceTemplate, st.TargetAdapter), w)
				return
			}
			for rolename, role := range v.AccessRoles {
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
								RoleUi:          role.Ui,
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
	common.SendResponse(proto.Message(&resp), w)
}

// GetViews implements the corresponding endpoint in the REST API.
func (s *Service) GetViews(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request method not supported: %q", r.Method), w)
		return
	}
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	name := getName(r)
	if err := checkName(name); err != nil {
		common.HandleError(http.StatusBadRequest, err, w)
		return
	}
	res, ok := cfg.Resources[name]
	if !ok {
		common.HandleError(http.StatusNotFound, fmt.Errorf("resource %q not found", name), w)
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
	common.SendResponse(proto.Message(&resp), w)
}

// GetView implements the corresponding endpoint in the REST API.
func (s *Service) GetView(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request method not supported: %q", r.Method), w)
		return
	}
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	name := getName(r)
	if err := checkName(name); err != nil {
		common.HandleError(http.StatusBadRequest, err, w)
		return
	}
	res, ok := cfg.Resources[name]
	if !ok {
		common.HandleError(http.StatusNotFound, fmt.Errorf("resource %q not found", name), w)
		return
	}
	viewName := mux.Vars(r)["view"]
	if err := checkName(viewName); err != nil {
		common.HandleError(http.StatusBadRequest, err, w)
		return
	}
	view, ok := res.Views[viewName]
	if !ok {
		common.HandleError(http.StatusNotFound, fmt.Errorf("resource %q view %q not found", name, viewName), w)
		return
	}
	resp := pb.GetViewResponse{
		View:   s.makeView(viewName, view, res, cfg),
		Access: s.makeAccessList(nil, []string{name}, []string{viewName}, nil, cfg, r),
	}
	common.SendResponse(proto.Message(&resp), w)
}

// GetViewRoles implements the corresponding endpoint in the REST API.
func (s *Service) GetViewRoles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request method not supported: %q", r.Method), w)
		return
	}
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	name := getName(r)
	if err := checkName(name); err != nil {
		common.HandleError(http.StatusBadRequest, err, w)
		return
	}
	res, ok := cfg.Resources[name]
	if !ok {
		common.HandleError(http.StatusNotFound, fmt.Errorf("resource %q not found", name), w)
		return
	}
	viewName := mux.Vars(r)["view"]
	if err := checkName(viewName); err != nil {
		common.HandleError(http.StatusBadRequest, err, w)
		return
	}
	view, ok := res.Views[viewName]
	if !ok {
		common.HandleError(http.StatusNotFound, fmt.Errorf("resource %q view %q not found", name, viewName), w)
		return
	}
	out := s.makeViewRoles(view, res, cfg)
	resp := pb.GetViewRolesResponse{
		Roles:  out,
		Access: s.makeAccessList(nil, []string{name}, []string{viewName}, nil, cfg, r),
	}
	common.SendResponse(proto.Message(&resp), w)
}

// GetViewRole implements the corresponding endpoint in the REST API.
func (s *Service) GetViewRole(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request method not supported: %q", r.Method), w)
		return
	}
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	name := getName(r)
	if err := checkName(name); err != nil {
		common.HandleError(http.StatusBadRequest, err, w)
		return
	}
	res, ok := cfg.Resources[name]
	if !ok {
		common.HandleError(http.StatusNotFound, fmt.Errorf("resource %q not found", name), w)
		return
	}
	vars := mux.Vars(r)
	viewName := vars["view"]
	if err := checkName(viewName); err != nil {
		common.HandleError(http.StatusBadRequest, err, w)
		return
	}
	view, ok := res.Views[viewName]
	if !ok {
		common.HandleError(http.StatusNotFound, fmt.Errorf("resource %q view %q not found", name, viewName), w)
		return
	}
	roleName := vars["role"]
	if err := checkName(roleName); err != nil {
		common.HandleError(http.StatusBadRequest, err, w)
		return
	}
	roles := s.makeViewRoles(view, res, cfg)
	role, ok := roles[roleName]
	if !ok {
		common.HandleError(http.StatusNotFound, fmt.Errorf("resource %q view %q role %q not found", name, viewName, roleName), w)
		return
	}
	resp := pb.GetViewRoleResponse{
		Role:   role,
		Access: s.makeAccessList(nil, []string{name}, []string{viewName}, []string{roleName}, cfg, r),
	}
	common.SendResponse(proto.Message(&resp), w)
}

// GetResourceToken implements the GetResourceToken RPC method.
func (s *Service) GetResourceToken(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]
	viewName := vars["view"]
	role, ok := vars["role"]
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

	var token string
	var acct string
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
	adapterAction := &adapter.Action{
		Aggregates:      aggregates,
		Identity:        id,
		Issuer:          getIssuerString(r),
		ClientID:        getClientID(r),
		Config:          cfg,
		GrantRole:       grantRole,
		MaxTTL:          maxTTL,
		Request:         r,
		Resource:        res,
		ServiceRole:     sRole,
		ServiceTemplate: st,
		TTL:             ttl,
		View:            view,
	}
	if acct, token, err = adapt.MintToken(adapterAction); err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}

	out := pb.GetTokenResponse{
		Name:    name,
		View:    s.makeView(viewName, view, res, cfg),
		Account: acct,
		Token:   token,
		Ttl:     common.TtlString(ttl),
	}
	common.SendResponse(proto.Message(&out), w)
}

func viewHasRole(view *pb.View, role string) bool {
	if view.AccessRoles == nil {
		return false
	}
	if _, ok := view.AccessRoles[role]; ok {
		return true
	}
	return false
}

func mergeLists(a, b []string) []string {
	m := make(map[string]bool)
	for _, v := range a {
		m[v] = true
	}
	for _, v := range b {
		m[v] = true
	}
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func roleCategorySet(input map[string]*pb.RoleCategory) []string {
	strs := make([]string, len(input))
	order := make(map[string]int)
	i := 0
	for k, v := range input {
		strs[i] = k
		order[k] = int(v.Order)
		i++
	}
	sort.Sort(&byOrder{
		strs:  strs,
		order: order,
	})
	return strs
}

type byOrder struct {
	strs  []string
	order map[string]int
}

func (srt byOrder) Len() int {
	return len(srt.strs)
}

func (srt byOrder) Less(i, j int) bool {
	return srt.order[srt.strs[i]] < srt.order[srt.strs[j]]
}

func (srt byOrder) Swap(i, j int) {
	srt.strs[i], srt.strs[j] = srt.strs[j], srt.strs[i]
}

func getIssuerString(r *http.Request) string {
	s := r.URL.Scheme
	if len(s) == 0 {
		// TODO: fix this.
		s = "https"
		if strings.HasPrefix(r.Host, "localhost") {
			s = "http"
		}
	}
	return s + "://" + r.Host
}

// GetTestResults implements the GetTestResults RPC method.
func (s *Service) GetTestResults(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	_, status, err := s.getPassportIdentity(cfg, nil, r)
	if err != nil {
		common.HandleError(status, err, w)
		return
	}
	common.SendResponse(proto.Message(s.runTests(cfg, nil)), w)
}

// ConfigHistory implements the HistoryConfig RPC method.
func (s *Service) ConfigHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request method not supported: %q", r.Method), w)
		return
	}
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	id, status, err := s.getPassportIdentity(cfg, nil, r)
	if err != nil {
		common.HandleError(status, err, w)
		return
	}
	if status, err := s.permissions.CheckAdmin(id); err != nil {
		common.HandleError(status, err, w)
		return
	}
	h, status, err := storage.GetHistory(s.store, storage.ConfigDatatype, getRealm(r), storage.DefaultUser, storage.DefaultID, r)
	if err != nil {
		common.HandleError(status, err, w)
	}
	common.SendResponse(h, w)
}

// ConfigHistoryRevision implements the HistoryRevisionConfig RPC method.
func (s *Service) ConfigHistoryRevision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request method not supported: %q", r.Method), w)
		return
	}
	name := getName(r)
	rev, err := strconv.ParseInt(name, 10, 64)
	if err != nil {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("invalid history revision: %q (must be a positive integer)", name), w)
		return
	}
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	id, status, err := s.getPassportIdentity(cfg, nil, r)
	if err != nil {
		common.HandleError(status, err, w)
		return
	}
	if status, err := s.permissions.CheckAdmin(id); err != nil {
		common.HandleError(status, err, w)
		return
	}
	cfg = &pb.DamConfig{}
	if status, err := s.realmReadTx(storage.ConfigDatatype, getRealm(r), storage.DefaultUser, storage.DefaultID, rev, cfg, nil); err != nil {
		common.HandleError(status, err, w)
		return
	}
	common.SendResponse(cfg, w)
}

// ConfigReset implements the corresponding method in the DAM API.
func (s *Service) ConfigReset(w http.ResponseWriter, r *http.Request) {
	// TODO: probably should not be a GET, but handy for now on a browser...
	if r.Method != http.MethodGet {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request method not supported: %q", r.Method), w)
		return
	}
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
	}
	id, status, err := s.getPassportIdentity(cfg, nil, r)
	if err != nil {
		common.HandleError(status, err, w)
		return
	}
	if status, err := s.permissions.CheckAdmin(id); err != nil {
		common.HandleError(status, err, w)
		return
	}
	if err = s.store.Wipe(storage.WipeAllRealms); err != nil {
		common.HandleError(http.StatusInternalServerError, err, w)
		return
	}
	if err = s.importFiles(); err != nil {
		common.HandleError(http.StatusInternalServerError, err, w)
		return
	}
}

// ConfigClientSecret implements the ClientSecretConfig RPC method.
func (s *Service) ConfigClientSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request method not supported: %q", r.Method), w)
		return
	}
	name := getName(r)

	tx, err := s.store.Tx(true)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, fmt.Errorf("configuration not available; try again later"), w)
		return
	}
	defer tx.Finish()

	cfg, err := s.loadConfig(tx, getRealm(r))
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	id, status, err := s.getPassportIdentity(cfg, tx, r)
	if err != nil {
		common.HandleError(status, err, w)
		return
	}
	if status, err := s.permissions.CheckAdmin(id); err != nil {
		common.HandleError(status, err, w)
		return
	}
	c := &pb.DamSecrets{}
	if status, err := s.realmReadTx(storage.SecretsDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, c, tx); err != nil {
		common.HandleError(status, err, w)
		return
	}
	if _, ok := c.ClientSecrets[name]; !ok {
		common.HandleError(http.StatusNotFound, fmt.Errorf("secret for client %q not found", name), w)
		return
	}
	delete(c.ClientSecrets, name)
	if err := s.saveSecrets(c, "DELETE client secret", "secret", r, id, tx); err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
}

// ConfigTestPersonas implements the ConfigTestPersonas RPC method.
func (s *Service) ConfigTestPersonas(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request method not supported: %q", r.Method), w)
		return
	}
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	id, status, err := s.getPassportIdentity(cfg, nil, r)
	if err != nil {
		common.HandleError(status, err, w)
		return
	}
	if status, err := s.permissions.CheckAdmin(id); err != nil {
		common.HandleError(status, err, w)
		return
	}
	out := &pb.GetTestPersonasResponse{
		Personas: cfg.TestPersonas,
	}
	common.SendResponse(out, w)
}

// ClientSecret implements the ClientSecret RPC method.
func (s *Service) ClientSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPatch {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request method not supported: %q", r.Method), w)
		return
	}
	tx, err := s.store.Tx(true)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, fmt.Errorf("configuration not available"), w)
		return
	}
	defer tx.Finish()

	cfg, err := s.loadConfig(tx, getRealm(r))
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	id, status, err := s.getPassportIdentity(cfg, tx, r)
	if err != nil {
		common.HandleError(status, err, w)
		return
	}
	cid := getClientID(r)
	var client *pb.Client
	for _, c := range cfg.Clients {
		if c.ClientId == cid {
			client = c
			break
		}
	}
	if client == nil {
		common.HandleError(http.StatusNotFound, fmt.Errorf("client %q not found", cid), w)
		return
	}
	secrets, err := s.loadSecrets(tx)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, fmt.Errorf("configuration unavailable; try again later"), w)
		return
	}
	desc := "Generate secret"
	qcs := getClientSecret(r)
	prev, ok := secrets.ClientSecrets[client.ClientId]
	if r.Method == http.MethodPost && ok {
		if qcs == prev {
			common.HandleError(http.StatusBadRequest, fmt.Errorf("update secret must be done via PATCH"), w)
			return
		}
		common.HandleError(http.StatusUnauthorized, fmt.Errorf("unauthorized client"), w)
		return
	} else if r.Method == http.MethodPatch {
		desc = "Update secret"
		if qcs != prev {
			common.HandleError(http.StatusUnauthorized, fmt.Errorf("unauthorized client"), w)
			return
		}
	}

	secret := common.GenerateGUID()
	secrets.ClientSecrets[client.ClientId] = secret
	if err := s.saveSecrets(secrets, desc, "secret", r, id, tx); err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	out := &pb.ClientSecretResponse{
		Secret: secret,
	}
	common.SendResponse(out, w)
}

// GetTargetAdapters implements the corresponding REST API endpoint.
func (s *Service) GetTargetAdapters(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request method not supported: %q", r.Method), w)
		return
	}
	out := &pb.TargetAdaptersResponse{
		TargetAdapters: s.adapters.Descriptors,
	}
	common.SendResponse(out, w)
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

	t, err = s.createIssuerTranslator(s.ctx, cfgTpi, secrets)
	if err != nil {
		return nil, fmt.Errorf("failed to create translator for issuer %q: %v", issuer, err)
	}
	s.translators.Store(issuer, t)
	return t, err
}

func (s *Service) createIssuerTranslator(ctx context.Context, cfgTpi *pb.TrustedPassportIssuer, secrets *pb.DamSecrets) (translator.Translator, error) {
	return translator.CreateTranslator(ctx, cfgTpi.Issuer, cfgTpi.TranslateUsing, cfgTpi.ClientId, secrets.PublicTokenKeys[cfgTpi.Issuer])
}

// GetPassportTranslators implements the corresponding REST API endpoint.
func (s *Service) GetPassportTranslators(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request method not supported: %q", r.Method), w)
		return
	}
	out := translator.GetPassportTranslators()
	common.SendResponse(out, w)
}

// GetDamRoleCategories implements the corresponding REST API method.
func (s *Service) GetDamRoleCategories(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request method not supported: %q", r.Method), w)
		return
	}
	out := &pb.DamRoleCategoriesResponse{
		DamRoleCategories: s.roleCategories,
	}
	common.SendResponse(out, w)
}

// GetTestPersonas implements the corresponding REST API method.
func (s *Service) GetTestPersonas(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request method not supported: %q", r.Method), w)
		return
	}
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	out := &pb.GetTestPersonasResponse{
		Personas:       cfg.TestPersonas,
		StandardClaims: playground.StandardClaims,
	}
	common.SendResponse(out, w)
}

//////////////////////////////////////////////////////////////////

func (s *Service) GetStore() storage.Store {
	return s.store
}

//////////////////////////////////////////////////////////////////

func (s *Service) realmFactory() *common.HandlerFactory {
	return &common.HandlerFactory{
		TypeName:            "realm",
		NameField:           "realm",
		PathPrefix:          realmPath,
		HasNamedIdentifiers: true,
		IsAdmin:             true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) common.HandlerInterface {
			return NewRealmHandler(s, w, r)
		},
	}
}

func (s *Service) processesFactory() *common.HandlerFactory {
	return &common.HandlerFactory{
		TypeName:            "processes",
		PathPrefix:          processesPath,
		HasNamedIdentifiers: false,
		IsAdmin:             true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) common.HandlerInterface {
			return NewProcessesHandler(s, w, r)
		},
	}
}

func (s *Service) processFactory() *common.HandlerFactory {
	return &common.HandlerFactory{
		TypeName:            "process",
		PathPrefix:          processPath,
		HasNamedIdentifiers: true,
		IsAdmin:             true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) common.HandlerInterface {
			return NewProcessHandler(s, w, r)
		},
	}
}

func (s *Service) configFactory() *common.HandlerFactory {
	return &common.HandlerFactory{
		TypeName:            "config",
		PathPrefix:          configPath,
		HasNamedIdentifiers: false,
		IsAdmin:             true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) common.HandlerInterface {
			return NewConfigHandler(s, w, r)
		},
	}
}

func (s *Service) configOptionsFactory() *common.HandlerFactory {
	return &common.HandlerFactory{
		TypeName:            "configOptions",
		PathPrefix:          configOptionsPath,
		HasNamedIdentifiers: false,
		IsAdmin:             true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) common.HandlerInterface {
			return NewConfigOptionsHandler(s, w, r)
		},
	}
}

func (s *Service) configResourceFactory() *common.HandlerFactory {
	return &common.HandlerFactory{
		TypeName:            "configResource",
		PathPrefix:          configResourcePath,
		HasNamedIdentifiers: true,
		IsAdmin:             true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) common.HandlerInterface {
			return NewConfigResourceHandler(s, w, r)
		},
	}
}

func (s *Service) configViewFactory() *common.HandlerFactory {
	return &common.HandlerFactory{
		TypeName:            "configView",
		PathPrefix:          configViewPath,
		HasNamedIdentifiers: true,
		IsAdmin:             true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) common.HandlerInterface {
			return NewConfigViewHandler(s, w, r)
		},
	}
}

func (s *Service) configIssuerFactory() *common.HandlerFactory {
	return &common.HandlerFactory{
		TypeName:            "configTrustedPassportIssuer",
		PathPrefix:          configTrustedPassportIssuerPath,
		HasNamedIdentifiers: true,
		IsAdmin:             true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) common.HandlerInterface {
			return NewConfigIssuerHandler(s, w, r)
		},
	}
}

func (s *Service) configSourceFactory() *common.HandlerFactory {
	return &common.HandlerFactory{
		TypeName:            "configTrustedSource",
		PathPrefix:          configTrustedSourcePath,
		HasNamedIdentifiers: true,
		IsAdmin:             true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) common.HandlerInterface {
			return NewConfigSourceHandler(s, w, r)
		},
	}
}

func (s *Service) configPolicyFactory() *common.HandlerFactory {
	return &common.HandlerFactory{
		TypeName:            "configPolicy",
		PathPrefix:          configPolicyPath,
		HasNamedIdentifiers: true,
		IsAdmin:             true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) common.HandlerInterface {
			return NewConfigPolicyHandler(s, w, r)
		},
	}
}

func (s *Service) configClaimDefinitionFactory() *common.HandlerFactory {
	return &common.HandlerFactory{
		TypeName:            "configClaimDefinition",
		PathPrefix:          configClaimDefPath,
		HasNamedIdentifiers: true,
		IsAdmin:             true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) common.HandlerInterface {
			return NewConfigClaimDefinitionHandler(s, w, r)
		},
	}
}

func (s *Service) configServiceTemplateFactory() *common.HandlerFactory {
	return &common.HandlerFactory{
		TypeName:            "configServiceTemplate",
		PathPrefix:          configServiceTemplatePath,
		HasNamedIdentifiers: true,
		IsAdmin:             true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) common.HandlerInterface {
			return NewConfigServiceTemplateHandler(s, w, r)
		},
	}
}

func (s *Service) configPersonaFactory() *common.HandlerFactory {
	return &common.HandlerFactory{
		TypeName:            "configTestPersona",
		PathPrefix:          configTestPersonaPath,
		HasNamedIdentifiers: true,
		IsAdmin:             true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) common.HandlerInterface {
			return NewConfigPersonaHandler(s, w, r)
		},
	}
}

func (s *Service) configClientFactory() *common.HandlerFactory {
	return &common.HandlerFactory{
		TypeName:            "configClient",
		PathPrefix:          configClientPath,
		HasNamedIdentifiers: true,
		IsAdmin:             true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) common.HandlerInterface {
			return NewConfigClientHandler(s, w, r)
		},
	}
}

/////////////////////////////////////////////////////////

func (s *Service) makeViews(r *pb.Resource, cfg *pb.DamConfig) map[string]*pb.View {
	out := make(map[string]*pb.View)
	for n, v := range r.Views {
		out[n] = s.makeView(n, v, r, cfg)
	}
	return out
}

func (s *Service) makeView(viewName string, v *pb.View, r *pb.Resource, cfg *pb.DamConfig) *pb.View {
	return &pb.View{
		ServiceTemplate:    v.ServiceTemplate,
		Version:            v.Version,
		Topic:              v.Topic,
		Partition:          v.Partition,
		Fidelity:           v.Fidelity,
		GeoLocation:        v.GeoLocation,
		ContentTypes:       v.ContentTypes,
		ComputedInterfaces: s.makeViewInterfaces(v, r, cfg),
		AccessRoles:        s.makeViewRoles(v, r, cfg),
		Ui:                 v.Ui,
	}
}

func (s *Service) makeViewInterfaces(srcView *pb.View, srcRes *pb.Resource, cfg *pb.DamConfig) map[string]*pb.View_Interface {
	out := make(map[string]*pb.View_Interface)
	entries, err := s.resolveAggregates(srcRes, srcView, cfg)
	if err != nil {
		return out
	}
	cliMap := make(map[string]map[string]bool)
	for _, entry := range entries {
		st, ok := cfg.ServiceTemplates[entry.View.ServiceTemplate]
		if !ok {
			return out
		}
		for _, item := range entry.View.Items {
			vars, err := adapter.GetItemVariables(s.adapters, st.TargetAdapter, st.ItemFormat, item)
			if err != nil {
				return out
			}
			for client, uriFmt := range st.Interfaces {
				uriMap, ok := cliMap[client]
				if !ok {
					uriMap = make(map[string]bool)
					cliMap[client] = uriMap
				}
				for k, v := range vars {
					uriFmt = strings.Replace(uriFmt, "${"+k+"}", v, -1)
				}
				if !hasItemVariable(uriFmt) {
					// Accept this string that has no more variables to replace.
					uriMap[uriFmt] = true
				}
			}
		}
	}
	for k, v := range cliMap {
		vi := &pb.View_Interface{
			Uri: []string{},
		}
		for uri := range v {
			vi.Uri = append(vi.Uri, uri)
		}
		sort.Strings(vi.Uri)
		out[k] = vi
	}
	return out
}

func hasItemVariable(str string) bool {
	return strings.Contains(str, "${")
}

func isItemVariable(str string) bool {
	return strings.HasPrefix(str, "${") && strings.HasSuffix(str, "}")
}

func (s *Service) makePolicyBasis(roleName string, srcView *pb.View, srcRes *pb.Resource, cfg *pb.DamConfig) []*pb.PolicyBasis {
	policies := make(map[string]bool)
	entries, err := s.resolveAggregates(srcRes, srcView, cfg)
	if err != nil {
		return []*pb.PolicyBasis{}
	}
	for _, entry := range entries {
		if role, ok := entry.View.AccessRoles[roleName]; ok {
			for _, policy := range role.Policies {
				policies[policy] = true
			}
		}
	}

	rmap := make(map[string]*pb.PolicyBasis)
	for rn := range policies {
		if _, ok := cfg.Policies[rn]; ok {
			addPolicyBasis("allow", cfg.Policies[rn].Allow, rmap)
			addPolicyBasis("disallow", cfg.Policies[rn].Disallow, rmap)
		}
	}

	require := make([]*pb.PolicyBasis, 0)
	for _, ro := range rmap {
		require = append(require, ro)
	}
	return require
}

func addPolicyBasis(clause string, cond *pb.Condition, rmap map[string]*pb.PolicyBasis) {
	if cond == nil {
		return
	}
	switch k := cond.Key.(type) {
	case *pb.Condition_Claim:
		mergePolicyBasis(k.Claim, "claim", clause, cond, rmap)
	case *pb.Condition_DataUse:
		mergePolicyBasis(k.DataUse, "duo", clause, cond, rmap)
	}
	for _, c := range cond.AllTrue {
		addPolicyBasis(clause, c, rmap)
	}
	for _, c := range cond.AnyTrue {
		addPolicyBasis(clause, c, rmap)
	}
}

func mergePolicyBasis(name, ptype, clause string, cond *pb.Condition, rmap map[string]*pb.PolicyBasis) {
	mname := "claim:" + name
	item, ok := rmap[mname]
	if !ok {
		item = &pb.PolicyBasis{
			Name:    name,
			Type:    ptype,
			Clauses: []string{clause},
		}
		rmap[mname] = item
	}
	found := false
	for _, c := range item.Clauses {
		if c == clause {
			found = true
			break
		}
	}
	if !found {
		item.Clauses = append(item.Clauses, clause)
		sort.Strings(item.Clauses)
	}
}

func (s *Service) makeViewRoles(view *pb.View, res *pb.Resource, cfg *pb.DamConfig) map[string]*pb.AccessRole {
	out := make(map[string]*pb.AccessRole)
	for rname, vRole := range view.AccessRoles {
		out[rname] = &pb.AccessRole{
			ComputedPolicyBasis: s.makePolicyBasis(rname, view, res, cfg),
			Ui:                  vRole.Ui,
		}
	}
	return out
}

func toTitle(str string) string {
	out := ""
	for i, ch := range str {
		if unicode.IsUpper(ch) && i > 0 && str[i-1] != ' ' {
			out += " "
		} else if ch == '_' {
			out += " "
			continue
		}
		out += string(ch)
	}
	return strings.Title(out)
}

func makeConfig(cfg *pb.DamConfig) *pb.DamConfig {
	out := &pb.DamConfig{}
	proto.Merge(out, cfg)
	out.Options = makeConfigOptions(cfg.Options)
	return out
}

func receiveConfig(cfg, origCfg *pb.DamConfig) *pb.DamConfig {
	cfg.Options = receiveConfigOptions(cfg.Options, origCfg)
	return cfg
}

func (s *Service) makeResource(name string, in *pb.Resource, cfg *pb.DamConfig) *pb.Resource {
	return &pb.Resource{
		Umbrella:    in.Umbrella,
		Views:       s.makeViews(in, cfg),
		Clients:     in.Clients,
		MaxTokenTtl: in.MaxTokenTtl,
		Ui:          in.Ui,
	}
}

func receiveResource(in *pb.Resource) *pb.Resource {
	// TODO: deep copy
	out := *in
	// Remove computed fields from views
	for k, v := range in.Views {
		out.Views[k] = receiveView(v)
	}
	return &out
}

func receiveView(in *pb.View) *pb.View {
	// TODO: deep copy
	out := *in
	out.ComputedInterfaces = nil
	if out.AccessRoles != nil {
		for _, r := range out.AccessRoles {
			r.ComputedPolicyBasis = nil
		}
	}
	return &out
}

func makeConfigOptions(opts *pb.ConfigOptions) *pb.ConfigOptions {
	out := &pb.ConfigOptions{}
	if opts != nil {
		proto.Merge(out, opts)
	}
	out.ComputedDescriptors = map[string]*pb.ConfigOptions_Descriptor{
		"readOnlyMasterRealm": &pb.ConfigOptions_Descriptor{
			Label:        "Read Only Master Realm",
			Description:  "When 'true', the master realm becomes read-only and updates to the configuration must be performed via updating a config file",
			Type:         "bool",
			DefaultValue: "false",
		},
		"whitelistedRealms": &pb.ConfigOptions_Descriptor{
			Label:       "Whitelisted Realms",
			Description: "By default any realm name can be created, but when this option is populated the DAM will only allow realms on this list to be created (the master realm is allowed implicitly)",
			Type:        "string",
			IsList:      true,
			Regexp:      "^[\\w\\-\\.]+$",
		},
		"gcpManagedKeysMaxRequestedTtl": &pb.ConfigOptions_Descriptor{
			Label:       "GCP Managed Keys Maximum Requested TTL",
			Description: "The maximum TTL of a requested access token on GCP and this setting is used in conjunction with managedKeysPerAccount to set up managed access key rotation policies within DAM (disabled by default)",
			Type:        "string:duration",
			Regexp:      common.DurationRegexpString,
			Min:         "2h",
			Max:         "180d",
		},
		"gcpManagedKeysPerAccount": &pb.ConfigOptions_Descriptor{
			Label:       "GCP Managed Keys Per Account",
			Description: "GCP allows up to 10 access keys of more than 1h to be active per account and this option allows DAM to manage a subset of these keys",
			Type:        "int",
			Min:         "0",
			Max:         "10",
		},
		"gcpServiceAccountProject": &pb.ConfigOptions_Descriptor{
			Label:       "GCP Service Account Project",
			Description: "The GCP Project ID where service accounts will be created by DAM and where DAM has permissions to create these service accounts (not setting this value will disable the service account target adapter)",
			Type:        "string",
			Regexp:      "^[A-Za-z][-A-Za-z0-9]{1,30}[A-Za-z]$",
		},
	}
	return out
}

func receiveConfigOptions(opts *pb.ConfigOptions, cfg *pb.DamConfig) *pb.ConfigOptions {
	out := &pb.ConfigOptions{}
	if opts != nil {
		proto.Merge(out, opts)
		out.ComputedDescriptors = nil
	}
	if cfg.Options.ReadOnlyMasterRealm {
		out.ReadOnlyMasterRealm = true
	}
	return out
}

func normalizeConfig(cfg *pb.DamConfig) error {
	if cfg.Clients == nil {
		cfg.Clients = make(map[string]*pb.Client)
	}
	for _, p := range cfg.TestPersonas {
		for aname, alist := range p.Resources {
			if alist == nil {
				alist = &pb.AccessList{}
				p.Resources[aname] = alist
			}
			if alist.Access == nil {
				alist.Access = []string{}
			}
			sort.Strings(alist.Access)
		}
	}
	return nil
}

func (s *Service) loadConfig(tx storage.Tx, realm string) (*pb.DamConfig, error) {
	cfg := &pb.DamConfig{}
	if _, err := s.realmReadTx(storage.ConfigDatatype, realm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, cfg, tx); err != nil {
		return nil, err
	}
	if err := normalizeConfig(cfg); err != nil {
		return nil, fmt.Errorf("invalid config file %q: %v", storage.ConfigDatatype, err)
	}
	return cfg, nil
}

func (s *Service) buildValidatorMap(cfg *pb.DamConfig) (map[string]*validator.Policy, error) {
	vm := make(map[string]*validator.Policy)
	policies, err := s.resolvePolicies(cfg)
	if err != nil {
		return nil, err
	}
	for pname, policy := range policies {
		v, err := validator.BuildPolicyValidator(s.ctx, policy, cfg.ClaimDefinitions, cfg.TrustedSources)
		if err != nil {
			return nil, fmt.Errorf("cannot build policy %q: %v", pname, err)
		}
		vm[pname] = v
	}
	return vm, nil
}

func (s *Service) resolvePolicies(cfg *pb.DamConfig) (map[string]*pb.Policy, error) {
	out := make(map[string]*pb.Policy)
	for resname, res := range cfg.Resources {
		for vname, view := range res.Views {
			for rolename, role := range view.AccessRoles {
				for _, p := range role.Policies {
					if len(p) > 0 && p[len(p)-1] == ')' {
						policy, err := s.resolvePolicyArgs(p, cfg)
						if err != nil {
							return nil, fmt.Errorf("resource %q view %q role %q: %v", resname, vname, rolename, err)
						}
						out[p] = policy
					} else {
						// Verify that no args were missing.
						policy, ok := cfg.Policies[p]
						if !ok {
							return nil, fmt.Errorf("resource %q view %q role %q: policy %q not found", resname, vname, rolename, p)
						}
						pargs := make(map[string][]string)
						used := make(map[string]bool)
						if err := resolveConditionArgs(policy.Allow, pargs, used); err != nil {
							return nil, fmt.Errorf("resource %q view %q role %q policy %q: %v", resname, vname, rolename, p, err)
						}
						if err := resolveConditionArgs(policy.Disallow, pargs, used); err != nil {
							return nil, fmt.Errorf("resource %q view %q role %q policy %q: %v", resname, vname, rolename, p, err)
						}
						// Now include it in the output if it is not already there.
						out[p] = policy
					}
				}
			}
		}
	}
	return out, nil
}

func (s *Service) resolvePolicyArgs(refPolicy string, cfg *pb.DamConfig) (*pb.Policy, error) {
	substr := strings.SplitN(refPolicy[0:len(refPolicy)-1], "(", 2)
	if len(substr) < 2 {
		return nil, fmt.Errorf("policy args %q: missing opening %q to arg list", refPolicy, "(")
	}
	pname := substr[0]
	argparts := strings.Split(substr[1], ";")
	src, ok := cfg.Policies[pname]
	if !ok {
		return nil, fmt.Errorf("policy reference %q: policy not found", pname)
	}
	policy := &pb.Policy{}
	proto.Merge(policy, src)
	pargs := make(map[string][]string)
	for apIdx, ap := range argparts {
		parts := strings.SplitN(ap, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("policy reference %q part %d: %q does not include an argument name of the form 'ARG=a,b,c,...'", refPolicy, apIdx+1, ap)
		}
		argname := parts[0]
		vals := strings.Split(parts[1], ",")
		if _, ok := pargs[argname]; ok {
			return nil, fmt.Errorf("policy reference %q defines arg %q more than once", refPolicy, argname)
		}
		pargs[argname] = vals
	}
	used := make(map[string]bool)
	if err := resolveConditionArgs(policy.Allow, pargs, used); err != nil {
		return nil, fmt.Errorf("policy reference %q error on allow clause: %v", refPolicy, err)
	}
	if err := resolveConditionArgs(policy.Disallow, pargs, used); err != nil {
		return nil, fmt.Errorf("policy reference %q error on disallow clause: %v", refPolicy, err)
	}
	if len(pargs) != len(used) {
		for k := range pargs {
			if _, ok := used[k]; !ok {
				return nil, fmt.Errorf("policy reference %q: arg %q is not defined", refPolicy, k)
			}
		}
	}
	return policy, nil
}

func resolveConditionArgs(cond *pb.Condition, args map[string][]string, used map[string]bool) error {
	if cond == nil {
		return nil
	}
	vals := []string{}
	for _, v := range cond.Values {
		if len(v) > 2 && strings.HasPrefix(v, "${") && strings.HasSuffix(v, "}") {
			argName := v[2 : len(v)-1]
			argVals, ok := args[argName]
			if !ok {
				return fmt.Errorf("policy arg %q was not provided as an input parameter", argName)
			}
			vals = append(vals, argVals...)
			used[argName] = true
		} else {
			vals = append(vals, v)
		}
	}
	cond.Values = vals
	for _, sub := range cond.AllTrue {
		if err := resolveConditionArgs(sub, args, used); err != nil {
			return err
		}
	}
	for _, sub := range cond.AnyTrue {
		if err := resolveConditionArgs(sub, args, used); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) saveConfig(cfg *pb.DamConfig, desc, resType string, r *http.Request, id *ga4gh.Identity, orig, update proto.Message, modification *pb.ConfigModification, tx storage.Tx) error {
	if update == nil {
		return nil
	}
	if modification != nil && modification.DryRun {
		return nil
	}
	cfg.Revision++
	cfg.CommitTime = float64(time.Now().UnixNano()) / 1e9
	if err := s.store.WriteTx(storage.ConfigDatatype, getRealm(r), storage.DefaultUser, storage.DefaultID, cfg.Revision, cfg, storage.MakeConfigHistory(desc, resType, cfg.Revision, cfg.CommitTime, r, id.Subject, orig, update), tx); err != nil {
		return fmt.Errorf("service storage unavailable: %v, retry later", err)
	}
	return nil
}

func (s *Service) saveSecrets(secrets *pb.DamSecrets, desc, resType string, r *http.Request, id *ga4gh.Identity, tx storage.Tx) error {
	secrets.Revision++
	secrets.CommitTime = float64(time.Now().UnixNano()) / 1e9
	if err := s.store.WriteTx(storage.SecretsDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, secrets.Revision, secrets, storage.MakeConfigHistory(desc, resType, secrets.Revision, secrets.CommitTime, r, id.Subject, nil, nil), tx); err != nil {
		return fmt.Errorf("service storage unavailable: %v, retry later", err)
	}
	return nil
}

func (s *Service) loadSecrets(tx storage.Tx) (*pb.DamSecrets, error) {
	secrets := &pb.DamSecrets{}
	_, err := s.realmReadTx(storage.SecretsDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, secrets, tx)
	if err != nil {
		return nil, err
	}
	return secrets, nil
}

func (s *Service) realmReadTx(datatype, realm, user, id string, rev int64, item proto.Message, tx storage.Tx) (int, error) {
	err := s.store.ReadTx(datatype, realm, user, id, rev, item, tx)
	if err == nil {
		return http.StatusOK, nil
	}
	if storage.ErrNotFound(err) && realm != storage.DefaultRealm {
		err = s.store.ReadTx(datatype, storage.DefaultRealm, user, id, rev, item, tx)
		if err == nil {
			return http.StatusOK, nil
		}
	}
	if storage.ErrNotFound(err) {
		if len(id) > 0 && id != storage.DefaultID {
			return http.StatusNotFound, fmt.Errorf("%s %q not found", datatype, id)
		}
		return http.StatusNotFound, fmt.Errorf("%s not found", datatype)
	}
	return http.StatusServiceUnavailable, fmt.Errorf("service storage unavailable: %v, retry later", err)
}

func (s *Service) registerProject(cfg *pb.DamConfig, realm string) error {
	if s.warehouse == nil {
		return nil
	}
	ttl, _ := common.ParseDuration(cfg.Options.GcpManagedKeysMaxRequestedTtl, maxTTL)
	return s.warehouse.RegisterAccountProject(realm, cfg.Options.GcpServiceAccountProject, int(ttl.Seconds()), int(cfg.Options.GcpManagedKeysPerAccount))
}

func (s *Service) unregisterRealm(cfg *pb.DamConfig, realm string) error {
	if s.warehouse == nil {
		return nil
	}
	return s.warehouse.RegisterAccountProject(realm, "", 0, 0)
}

func (s *Service) importFiles() error {
	if isAutoReset() {
		wipe := false
		cfg, err := s.loadConfig(nil, storage.DefaultRealm)
		if err != nil {
			if !storage.ErrNotFound(err) {
				wipe = true
			}
		} else if err := s.CheckIntegrity(cfg); err != nil {
			wipe = true
		}
		if wipe {
			log.Printf("prepare for DAM config import: wipe data store for all realms")
			if err = s.store.Wipe(storage.WipeAllRealms); err != nil {
				return err
			}
		}
	}

	ok, err := s.store.Exists(storage.SecretsDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	log.Printf("import DAM config into data store")
	fs := getFileStore(s.store, inheritService)
	tx, err := s.store.Tx(true)
	if err != nil {
		return err
	}
	defer tx.Finish()

	history := &pb.HistoryEntry{
		Revision:   1,
		User:       "admin",
		CommitTime: float64(time.Now().Unix()),
		Desc:       "Initial config",
	}
	cfg := &pb.DamConfig{}

	if err = fs.Read(storage.ConfigDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, cfg); err != nil {
		return err
	}
	history.Revision = cfg.Revision
	if err = s.store.WriteTx(storage.ConfigDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, cfg.Revision, cfg, history, tx); err != nil {
		return err
	}
	secrets := &pb.DamSecrets{}
	if err = fs.Read(storage.SecretsDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, secrets); err != nil {
		return err
	}
	history.Revision = secrets.Revision
	if err = s.store.WriteTx(storage.SecretsDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, secrets.Revision, secrets, history, tx); err != nil {
		return err
	}
	return s.registerProject(cfg, storage.DefaultRealm)
}

func isAutoReset() bool {
	return os.Getenv("IMPORT") == "AUTO_RESET"
}

func getFileStore(store storage.Store, service string) storage.Store {
	info := store.Info()
	if service == inheritService {
		service = info["service"]
	}
	path := info["path"]
	return storage.NewFileStorage(service, path)
}
