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

// Package dam contains data access management service.
package dam

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/golang/protobuf/jsonpb" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
	"cloud.google.com/go/logging" /* copybara-comment: logging */
	"github.com/gorilla/mux" /* copybara-comment */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"golang.org/x/oauth2" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/adapter" /* copybara-comment: adapter */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/auth" /* copybara-comment: auth */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds" /* copybara-comment: clouds */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common" /* copybara-comment: common */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/handlerfactory" /* copybara-comment: handlerfactory */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/oathclients" /* copybara-comment: oathclients */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/permissions" /* copybara-comment: permissions */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/persona" /* copybara-comment: persona */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/translator" /* copybara-comment: translator */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/validator" /* copybara-comment: validator */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/verifier" /* copybara-comment: verifier */

	glog "github.com/golang/glog" /* copybara-comment */
	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
)

const (
	maxNameLength = 32
	minNameLength = 3
	clientIdLen   = 36

	noClientID          = ""
	noScope             = ""
	defaultPersonaScope = ""
	damStaticService    = "dam-static"
)

var (
	ttlRE = regexp.MustCompile(`^[0-9]+[smhdw]$`)

	defaultTTL             = 1 * time.Hour
	defaultMaxRequestedTTL = 14 * 24 * time.Hour
	maxTTL                 = 90 * 24 * time.Hour // keep in sync with maxTTLStr
	maxTTLStr              = "90 days"           // keep in sync with maxTTL

	translators = translator.PassportTranslators()

	importDefault = os.Getenv("IMPORT")
)

type Service struct {
	adapters         *adapter.TargetAdapters
	roleCategories   map[string]*pb.RoleCategory
	domainURL        string
	defaultBroker    string
	serviceName      string
	hydraAdminURL    string
	hydraPublicURL   string
	store            storage.Store
	warehouse        clouds.ResourceTokenCreator
	logger           *logging.Client
	permissions      *permissions.Permissions
	Handler          *ServiceHandler
	hidePolicyBasis  bool
	hideRejectDetail bool
	httpClient       *http.Client
	startTime        int64
	translators      sync.Map
	useHydra         bool
	visaVerifier     *verifier.Verifier
}

type ServiceHandler struct {
	Handler *mux.Router
	s       *Service
}

// Options contains parameters to New DAM Service.
type Options struct {
	// HTTPClient: http client for making http request.
	HTTPClient *http.Client
	// Domain: domain used to host DAM service
	Domain string
	// ServiceName: name of this service instance including environment (example: "dam-staging")
	ServiceName string
	// DefaultBroker: default identity broker
	DefaultBroker string
	// Store: data storage and configuration storage
	Store storage.Store
	// Warehouse: resource token creator service
	Warehouse clouds.ResourceTokenCreator
	// Logger: audit log logger
	Logger *logging.Client
	// UseHydra: service use hydra integrated OIDC.
	UseHydra bool
	// HydraAdminURL: hydra admin endpoints url
	HydraAdminURL string
	// HydraPublicURL: hydra public endpoints url
	HydraPublicURL string
	// HidePolicyBasis: do not send policy basis to client
	HidePolicyBasis bool
	// HideRejectDetail: do not send rejected visas details
	HideRejectDetail bool
}

// NewService create DAM service
func NewService(params *Options) *Service {
	fs := getFileStore(params.Store, damStaticService)
	var roleCat pb.DamRoleCategoriesResponse
	if err := fs.Read("role", storage.DefaultRealm, storage.DefaultUser, "en", storage.LatestRev, &roleCat); err != nil {
		glog.Fatalf("cannot load role categories: %v", err)
	}
	perms, err := permissions.LoadPermissions(params.Store)
	if err != nil {
		glog.Fatalf("cannot load permissions: %v", err)
	}

	sh := &ServiceHandler{}
	s := &Service{
		roleCategories:   roleCat.DamRoleCategories,
		domainURL:        params.Domain,
		defaultBroker:    params.DefaultBroker,
		serviceName:      params.ServiceName,
		store:            params.Store,
		warehouse:        params.Warehouse,
		logger:           params.Logger,
		permissions:      perms,
		Handler:          sh,
		hidePolicyBasis:  params.HidePolicyBasis,
		hideRejectDetail: params.HideRejectDetail,
		httpClient:       params.HTTPClient,
		startTime:        time.Now().Unix(),
		useHydra:         params.UseHydra,
		hydraAdminURL:    params.HydraAdminURL,
		hydraPublicURL:   params.HydraPublicURL,
		visaVerifier:     verifier.New(""),
	}

	if s.httpClient == nil {
		s.httpClient = http.DefaultClient
	}

	secrets, err := s.loadSecrets(nil)
	if err != nil {
		if isAutoReset() || storage.ErrNotFound(err) {
			if impErr := s.ImportFiles(importDefault); impErr == nil {
				secrets, err = s.loadSecrets(nil)
			}
		}
		if err != nil {
			glog.Fatalf("cannot load client secrets: %v", err)
		}
	}
	adapters, err := adapter.CreateAdapters(fs, params.Warehouse, secrets)
	if err != nil {
		glog.Fatalf("cannot load adapters: %v", err)
	}
	s.adapters = adapters
	if err := s.ImportFiles(importDefault); err != nil {
		glog.Fatalf("cannot initialize storage: %v", err)
	}
	cfg, err := s.loadConfig(nil, storage.DefaultRealm)
	if err != nil {
		glog.Fatalf("cannot load config: %v", err)
	}
	if stat := s.CheckIntegrity(cfg); stat != nil {
		glog.Fatalf("config integrity error: %+v", stat.Proto())
	}
	if err = s.updateWarehouseOptions(cfg.Options, storage.DefaultRealm, nil); err != nil {
		glog.Fatalf("setting service account config options failed (cannot enforce access management policies): %v", err)
	}
	if err = s.registerAllProjects(nil); err != nil {
		glog.Fatalf("registation of one or more service account projects failed (cannot enforce access management policies): %v", err)
	}

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, s.httpClient)
	if tests := s.runTests(ctx, cfg, nil); hasTestError(tests) {
		glog.Fatalf("run tests error: %v; results: %v; modification: <%v>", tests.Error, tests.TestResults, tests.Modification)
	}

	for name, cfgTpi := range cfg.TrustedPassportIssuers {
		_, err = s.getIssuerTranslator(ctx, cfgTpi.Issuer, cfg, secrets, nil)
		if err != nil {
			glog.Infof("failed to create translator for issuer %q: %v", name, err)
		}
	}

	sh.s = s
	sh.Handler = mux.NewRouter()
	registerHandlers(sh.Handler, s)
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

func (s *Service) handlerSetup(tx storage.Tx, r *http.Request, scope string, item proto.Message) (*pb.DamConfig, *ga4gh.Identity, int, error) {
	if item != nil {
		if err := jsonpb.Unmarshal(r.Body, item); err != nil && err != io.EOF {
			return nil, nil, http.StatusBadRequest, err
		}
	}
	cfg, err := s.loadConfig(tx, getRealm(r))
	if err != nil {
		return nil, nil, http.StatusServiceUnavailable, err
	}
	id, status, err := s.getBearerTokenIdentity(cfg, r)
	if err != nil {
		return nil, nil, status, err
	}
	return cfg, id, status, err
}

func (sh *ServiceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "OPTIONS" {
		httputil.WriteCorsHeaders(w)
		w.WriteHeader(http.StatusOK)
		return
	}

	// Inject http client for oauth lib.
	r = r.WithContext(context.WithValue(r.Context(), oauth2.HTTPClient, sh.s.httpClient))

	sh.Handler.ServeHTTP(w, r)
}

func checkName(name string) error {
	return httputil.CheckName("name", name, nil)
}

func (s *Service) getIssuerString() string {
	if s.useHydra {
		return strings.TrimRight(s.hydraPublicURL, "/") + "/"
	}

	return ""
}

func (s *Service) damSignedBearerTokenToPassportIdentity(ctx context.Context, cfg *pb.DamConfig, tok, clientID string) (*ga4gh.Identity, error) {
	id, err := common.ConvertTokenToIdentityUnsafe(tok)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, fmt.Sprintf("inspecting token: %v", err))
	}

	v, err := common.GetOIDCTokenVerifier(ctx, clientID, id.Issuer)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, fmt.Sprintf("GetOIDCTokenVerifier failed: %v", err))
	}

	if _, err = v.Verify(ctx, tok); err != nil {
		return nil, status.Errorf(codes.Unavailable, fmt.Sprintf("token unauthorized: %v", err))
	}

	// TODO: add more checks here as appropriate.
	iss := s.getIssuerString()
	if err = id.Valid(); err != nil {
		return nil, status.Errorf(codes.Unauthenticated, fmt.Sprintf("token invalid: %v", err))
	}
	if id.Issuer != iss {
		return nil, status.Errorf(codes.Unauthenticated, fmt.Sprintf("bearer token unauthorized for issuer %q", id.Issuer))
	}
	if !common.IsAudience(id, clientID, iss) {
		return nil, status.Errorf(codes.Unauthenticated, "bearer token unauthorized party")
	}

	if !s.useHydra {
		return id, nil
	}

	l, ok := id.Extra["identities"]
	if !ok {
		return id, nil
	}

	list, ok := l.([]interface{})
	if !ok {
		return nil, status.Errorf(codes.Internal, "id.Extra[identities] in wrong type")
	}

	if id.Identities == nil {
		id.Identities = map[string][]string{}
	}

	for i, it := range list {
		identity, ok := it.(string)
		if !ok {
			return nil, status.Errorf(codes.Internal, fmt.Sprintf("id.Extra[identities][%d] in wrong type", i))
		}

		id.Identities[identity] = nil
	}

	return id, nil
}

func (s *Service) upstreamTokenToPassportIdentity(ctx context.Context, cfg *pb.DamConfig, tx storage.Tx, tok, clientID string) (*ga4gh.Identity, error) {
	id, err := common.ConvertTokenToIdentityUnsafe(tok)
	if err != nil {
		return nil, fmt.Errorf("inspecting token: %v", err)
	}

	iss := id.Issuer
	t, err := s.getIssuerTranslator(ctx, iss, cfg, nil, tx)
	if err != nil {
		return nil, err
	}

	id, err = t.TranslateToken(ctx, tok)
	if err != nil {
		return nil, fmt.Errorf("translating token from issuer %q: %v", iss, err)
	}
	if common.HasUserinfoClaims(id) {
		id, err = translator.FetchUserinfoClaims(ctx, id, tok, t)
		if err != nil {
			return nil, fmt.Errorf("fetching user info from issuer %q: %v", iss, err)
		}
	}

	if err := id.Validate(clientID); err != nil {
		return nil, err
	}

	return s.populateIdentityVisas(ctx, id, cfg)
}

func (s *Service) populateIdentityVisas(ctx context.Context, id *ga4gh.Identity, cfg *pb.DamConfig) (*ga4gh.Identity, error) {
	// Filter visas by trusted issuers.
	trusted := trustedIssuers(cfg.TrustedPassportIssuers)
	vs := []ga4gh.VisaJWT{}
	for i, v := range id.VisaJWTs {
		jwt := ga4gh.VisaJWT(v)
		v, err := ga4gh.NewVisaFromJWT(jwt)
		if err != nil {
			id.RejectVisa(nil, ga4gh.UnspecifiedVisaFormat, "invalid_visa", "", fmt.Sprintf("cannot unpack visa %d", i))
		}
		d := v.Data()
		if _, ok := trusted[d.Issuer]; !ok {
			id.RejectVisa(d, v.Format(), "untrusted_issuer", "iss", fmt.Sprintf("issuer %q is not a trusted author of visas by the DAM", d.Issuer))
			continue
		}
		vs = append(vs, jwt)
	}
	claims, _, err := ga4gh.VisasToOldClaims(ctx, vs, s.visaVerifier.Verify)
	if err != nil {
		return nil, err
	}
	id.GA4GH = claims

	return id, nil
}

func trustedIssuers(trustedIssuers map[string]*pb.TrustedPassportIssuer) map[string]bool {
	trusted := make(map[string]bool)
	for _, tpi := range trustedIssuers {
		trusted[tpi.Issuer] = true
	}
	return trusted
}

func (s *Service) getBearerTokenIdentity(cfg *pb.DamConfig, r *http.Request) (*ga4gh.Identity, int, error) {
	tok, err := extractBearerToken(r)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}

	id, err := s.damSignedBearerTokenToPassportIdentity(r.Context(), cfg, tok, getClientID(r))
	if err != nil {
		return nil, http.StatusUnauthorized, err
	}
	return id, http.StatusOK, nil
}

func (s *Service) getPassportIdentity(cfg *pb.DamConfig, tx storage.Tx, r *http.Request) (*ga4gh.Identity, int, error) {
	tok, err := extractBearerToken(r)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}

	id, err := s.upstreamTokenToPassportIdentity(r.Context(), cfg, tx, tok, getClientID(r))
	if err != nil {
		return nil, http.StatusUnauthorized, err
	}
	return id, http.StatusOK, nil
}

func (s *Service) testPersona(ctx context.Context, personaName string, resources []string, cfg *pb.DamConfig) (string, []string, error) {
	p := cfg.TestPersonas[personaName]
	id, err := persona.ToIdentity(personaName, p, defaultPersonaScope, "")
	if err != nil {
		return "INVALID", nil, err
	}
	state, got, err := s.resolveAccessList(ctx, id, resources, nil, nil, cfg)
	if err != nil {
		return state, got, err
	}
	if reflect.DeepEqual(p.Access, got) || (len(p.Access) == 0 && len(got) == 0) {
		return "PASSED", got, nil
	}
	return "FAILED", got, fmt.Errorf("access does not match expectations")
}

// syncToHydra pushes the configuration of clients and secrets to Hydra.
// Use minFrequency of 0 if you always want the sync to proceed immediately after
// the last one (if it doesn't time out), or non-zero to indicate that a recent sync
// is good enough. Note there are some race conditions with several client changes
// overlapping in flight that could still have the two services be out of sync.
func (s *Service) syncToHydra(clients map[string]*cpb.Client, secrets map[string]string, minFrequency time.Duration, tx storage.Tx) error {
	if !s.useHydra {
		return nil
	}
	ltx := s.store.LockTx("hydra_"+s.serviceName, minFrequency, tx)
	if ltx == nil {
		return nil
	}
	if tx == nil {
		// Is a new tx (i.e. ltx didn't override tx)
		defer ltx.Finish()
	}
	if err := oathclients.ResetClients(s.httpClient, s.hydraAdminURL, clients, secrets); err != nil {
		glog.Errorf("failed to sync hydra clients: %v", err)
		return err
	}
	return nil
}

func (s *Service) resolveAccessList(ctx context.Context, id *ga4gh.Identity, resources, views, roles []string, cfg *pb.DamConfig) (string, []string, error) {
	var got []string
	for _, rn := range resources {
		r, ok := cfg.Resources[rn]
		if !ok {
			sort.Strings(got)
			return "FAILED", got, fmt.Errorf("resource %q not found", rn)
		}
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
				if _, err := s.checkAuthorization(ctx, id, 0, rn, vn, rname, cfg, noClientID); err != nil {
					continue
				}
				got = append(got, rn+"/"+vn+"/"+rname)
			}
		}
	}
	sort.Strings(got)
	return "OK", got, nil
}

func (s *Service) makeAccessList(id *ga4gh.Identity, resources, views, roles []string, cfg *pb.DamConfig, r *http.Request) []string {
	// Ignore errors as the goal of makeAccessList is to show what is accessible despite any errors.
	// TODO: consider separating acceptable errors (don't halt the request) from system errors that should return an error code.
	if id == nil {
		var err error
		id, _, err = s.getPassportIdentity(cfg, nil, r)
		if err != nil {
			return nil
		}
	}
	_, got, err := s.resolveAccessList(r.Context(), id, resources, views, roles, cfg)
	if err != nil {
		return nil
	}
	return got
}

func (s *Service) checkAuthorization(ctx context.Context, id *ga4gh.Identity, ttl time.Duration, resourceName, viewName, roleName string, cfg *pb.DamConfig, client string) (int, error) {
	if stat := s.checkTrustedIssuer(id.Issuer, cfg); stat != nil {
		return httputil.HTTPStatus(stat.Code()), stat.Err()
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
		ctxWithTTL := context.WithValue(ctx, validator.RequestTTLInNanoFloat64, float64(ttl.Nanoseconds())/1e9)
		for _, p := range vRole.Policies {
			v, err := s.buildValidator(ctxWithTTL, p, vRole, cfg)
			if err != nil {
				return http.StatusInternalServerError, fmt.Errorf("cannot enforce policies for resource %q view %q role %q: %v", resourceName, viewName, roleName, err)
			}
			ok, err = v.Validate(ctxWithTTL, id)
			if err != nil {
				// Strip internal error in case it contains any sensitive data.
				return http.StatusInternalServerError, fmt.Errorf("cannot validate identity (subject %q, issuer %q): internal error", id.Subject, id.Issuer)
			}
			if !ok {
				rejected := s.rejectedPolicyString(id.RejectedVisas, s.makePolicyBasis(roleName, view, res, cfg))
				return http.StatusForbidden, fmt.Errorf("unauthorized for resource %q view %q role %q (policy requirements failed)\n\n%s", resourceName, viewName, roleName, rejected)
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
		vars, _, err := adapter.GetItemVariables(s.adapters, st.TargetAdapter, st.ItemFormat, item)
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

//////////////////////////////////////////////////////////////////

func (s *Service) GetStore() storage.Store {
	return s.store
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

func (s *Service) makeViewInterfaces(srcView *pb.View, srcRes *pb.Resource, cfg *pb.DamConfig) map[string]*pb.Interface {
	out := make(map[string]*pb.Interface)
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
			vars, _, err := adapter.GetItemVariables(s.adapters, st.TargetAdapter, st.ItemFormat, item)
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
		vi := &pb.Interface{
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

func (s *Service) makeRoleCategories(view *pb.View, role string, cfg *pb.DamConfig) []string {
	st, ok := cfg.ServiceTemplates[view.ServiceTemplate]
	if !ok {
		return nil
	}
	sr, ok := st.ServiceRoles[role]
	if !ok {
		return nil
	}
	sort.Strings(sr.DamRoleCategories)
	return sr.DamRoleCategories
}

func hasItemVariable(str string) bool {
	return strings.Contains(str, "${")
}

func isItemVariable(str string) bool {
	return strings.HasPrefix(str, "${") && strings.HasSuffix(str, "}")
}

type rejectedPolicy struct {
	Rejections    int                   `json:"rejections"`
	RejectedVisas []*ga4gh.RejectedVisa `json:"rejectedVisas,omitempty"`
	PolicyBasis   []string              `json:"policyBasis,omitempty"`
}

func (s *Service) rejectedPolicyString(rejected []*ga4gh.RejectedVisa, policyBasis map[string]bool) string {
	rejections := len(rejected)
	if s.hideRejectDetail {
		rejected = nil
	}
	var basis []string
	if !s.hidePolicyBasis {
		for k := range policyBasis {
			basis = append(basis, k)
		}
	}
	detail := &rejectedPolicy{
		Rejections:    rejections,
		RejectedVisas: rejected,
		PolicyBasis:   basis,
	}
	b, err := json.Marshal(detail)
	if err != nil {
		// Already in the error state and this is optional detail, just return something.
		return fmt.Sprintf(`{"rejections":%d}`, rejections)
	}
	return string(b)
}

func (s *Service) makePolicyBasis(roleName string, srcView *pb.View, srcRes *pb.Resource, cfg *pb.DamConfig) map[string]bool {
	if s.hidePolicyBasis {
		return nil
	}
	policies := make(map[string]bool)
	entries, err := s.resolveAggregates(srcRes, srcView, cfg)
	if err != nil {
		return nil
	}
	for _, entry := range entries {
		if role, ok := entry.View.AccessRoles[roleName]; ok {
			for _, p := range role.Policies {
				policies[p.Name] = true
			}
		}
	}

	basis := make(map[string]bool)
	for rn := range policies {
		if _, ok := cfg.Policies[rn]; ok {
			addPolicyBasis(cfg.Policies[rn], basis)
		}
	}
	return basis
}

func addPolicyBasis(p *pb.Policy, basis map[string]bool) {
	if p == nil {
		return
	}
	for _, any := range p.AnyOf {
		for _, clause := range any.AllOf {
			basis[clause.Type] = true
		}
	}
}

func (s *Service) makeViewRoles(view *pb.View, res *pb.Resource, cfg *pb.DamConfig) map[string]*pb.AccessRole {
	out := make(map[string]*pb.AccessRole)
	for rname := range view.AccessRoles {
		out[rname] = &pb.AccessRole{
			ComputedRoleCategories: s.makeRoleCategories(view, rname, cfg),
			ComputedPolicyBasis:    s.makePolicyBasis(rname, view, res, cfg),
		}
	}
	return out
}

func makeConfig(cfg *pb.DamConfig) *pb.DamConfig {
	out := &pb.DamConfig{}
	proto.Merge(out, cfg)
	out.Options = makeConfigOptions(cfg.Options)
	return out
}

func receiveConfig(cfg, origCfg *pb.DamConfig) *pb.DamConfig {
	for k, v := range cfg.Resources {
		cfg.Resources[k] = receiveResource(v)
	}
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
		"readOnlyMasterRealm": {
			Label:        "Read Only Master Realm",
			Description:  "When 'true', the master realm becomes read-only and updates to the configuration must be performed via updating a config file",
			Type:         "bool",
			DefaultValue: "false",
		},
		"whitelistedRealms": {
			Label:       "Whitelisted Realms",
			Description: "By default any realm name can be created, but when this option is populated the DAM will only allow realms on this list to be created (the master realm is allowed implicitly)",
			Type:        "string",
			IsList:      true,
			Regexp:      "^[\\w\\-\\.]+$",
		},
		"gcpManagedKeysMaxRequestedTtl": {
			Label:        "GCP Managed Keys Maximum Requested TTL",
			Description:  "The maximum TTL of a requested access token on GCP and this setting is used in conjunction with managedKeysPerAccount to set up managed access key rotation policies within DAM (disabled by default)",
			Type:         "string:duration",
			Regexp:       common.DurationRegexpString,
			Min:          "2h",
			Max:          "180d",
			DefaultValue: common.TTLString(defaultMaxRequestedTTL),
		},
		"gcpManagedKeysPerAccount": {
			Label:        "GCP Managed Keys Per Account",
			Description:  "GCP allows up to 10 access keys of more than 1h to be active per account and this option allows DAM to manage a subset of these keys",
			Type:         "int",
			Min:          "0",
			Max:          "10",
			DefaultValue: "10",
		},
		"gcpServiceAccountProject": {
			Label:       "GCP Service Account Project",
			Description: "The GCP Project ID where service accounts will be created by DAM and where DAM has permissions to create these service accounts (not setting this value will disable the service account target adapter)",
			Type:        "string",
			// See the documentation on GCP project ID.
			// https://cloud.google.com/resource-manager/reference/rest/v1/projects
			Regexp: "^[A-Za-z][-A-Za-z0-9]{4,28}[A-Za-z0-9]$",
		},
		"gcpIamBillingProject": {
			Label:       "GCP IAM Billing Project",
			Description: "The GCP Project ID that DAM can use for billing when making API calls that require a billing account (e.g. IAM calls on requester-pays buckets). If unset, billing will inherit the gcpServiceAccountProject setting.",
			Type:        "string",
			// See the documentation on GCP project ID.
			// https://cloud.google.com/resource-manager/reference/rest/v1/projects
			Regexp: "^[A-Za-z][-A-Za-z0-9]{4,28}[A-Za-z0-9]$",
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
		cfg.Clients = make(map[string]*cpb.Client)
	}
	for _, p := range cfg.TestPersonas {
		sort.Strings(p.Access)
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

	// glog.Infof("loaded DAM config: %+v", cfg)
	return cfg, nil
}

func (s *Service) buildValidator(ctx context.Context, ap *pb.AccessRole_AccessPolicy, accessRole *pb.AccessRole, cfg *pb.DamConfig) (*validator.Policy, error) {
	policy, ok := cfg.Policies[ap.Name]
	if !ok {
		return nil, fmt.Errorf("access policy name %q does not match any policy names", ap.Name)
	}
	return validator.BuildPolicyValidator(ctx, policy, cfg.ClaimDefinitions, cfg.TrustedSources, ap.Vars)
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

func (s *Service) registerAllProjects(tx storage.Tx) error {
	if s.warehouse == nil {
		return nil
	}
	projects := make(map[string]bool)
	offset := 0
	pageSize := 50
	for {
		content := make(map[string]map[string]proto.Message)
		count, err := s.store.MultiReadTx(storage.ConfigDatatype, storage.AllRealms, storage.DefaultUser, nil, offset, pageSize, content, &pb.DamConfig{}, tx)
		if err != nil {
			return err
		}
		if count == 0 || len(content) == 0 {
			break
		}
		offset += count
		for _, userVal := range content {
			for _, v := range userVal {
				if cfg, ok := v.(*pb.DamConfig); ok && len(cfg.Options.GcpServiceAccountProject) > 0 {
					projects[cfg.Options.GcpServiceAccountProject] = true
				}
			}
		}
		if count < pageSize {
			break
		}
	}
	for p := range projects {
		if err := s.registerProject(p, tx); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) registerProject(project string, tx storage.Tx) error {
	if s.warehouse == nil {
		return nil
	}
	return s.warehouse.RegisterAccountProject(project, tx)
}

func (s *Service) unregisterProject(project string, tx storage.Tx) error {
	if s.warehouse == nil {
		return nil
	}
	return s.warehouse.UnregisterAccountProject(project, tx)
}

func (s *Service) updateWarehouseOptions(opts *pb.ConfigOptions, realm string, tx storage.Tx) error {
	if s.warehouse == nil || realm != storage.DefaultRealm {
		return nil
	}
	ttl, _ := common.ParseDuration(opts.GcpManagedKeysMaxRequestedTtl, defaultMaxRequestedTTL)
	keys := int(opts.GcpManagedKeysPerAccount)
	return s.warehouse.UpdateSettings(ttl, keys, tx)
}

// ImportFiles ingests bootstrap configuration files to the DAM's storage sytem.
func (s *Service) ImportFiles(importType string) error {
	wipe := false
	switch importType {
	case "AUTO_RESET":
		cfg, err := s.loadConfig(nil, storage.DefaultRealm)
		if err != nil {
			if !storage.ErrNotFound(err) {
				wipe = true
			}
		} else if err := s.CheckIntegrity(cfg); err != nil {
			wipe = true
		}
	case "FORCE_WIPE":
		wipe = true
	}
	if wipe {
		glog.Infof("prepare for DAM config import: wipe data store for all realms")
		if err := s.store.Wipe(storage.AllRealms); err != nil {
			return err
		}
	}

	ok, err := s.store.Exists(storage.SecretsDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	fs := getFileStore(s.store, os.Getenv("IMPORT_SERVICE"))
	glog.Infof("import DAM config %q into data store", fs.Info()["service"])
	tx, err := s.store.Tx(true)
	if err != nil {
		return err
	}
	defer tx.Finish()

	history := &cpb.HistoryEntry{
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
	return s.registerProject(cfg.Options.GcpServiceAccountProject, tx)
}

func isAutoReset() bool {
	return importDefault == "AUTO_RESET"
}

func getFileStore(store storage.Store, service string) storage.Store {
	info := store.Info()
	if len(service) == 0 {
		// Inherit service name from existing store.
		service = info["service"]
	}
	path := info["path"]
	return storage.NewFileStorage(service, path)
}

// TODO: move registeration of endpoints to main package.
func registerHandlers(r *mux.Router, s *Service) {
	a := &authChecker{s: s}
	checker := &auth.Checker{
		Logger:             s.logger,
		Issuer:             s.getIssuerString(),
		FetchClientSecrets: a.fetchClientSecrets,
		IsAdmin:            a.isAdmin,
		TransformIdentity:  a.transformIdentity,
	}

	// info endpoint
	r.HandleFunc(infoPath, auth.MustWithAuth(s.GetInfo, checker, auth.RequireNone)).Methods(http.MethodGet)

	// readonly config endpoints
	r.HandleFunc(clientPath, auth.MustWithAuth(handlerfactory.MakeHandler(s, s.clientFactory()), checker, auth.RequireClientIDAndSecret))
	r.HandleFunc(resourcesPath, auth.MustWithAuth(s.GetResources, checker, auth.RequireClientIDAndSecret)).Methods(http.MethodGet)
	r.HandleFunc(resourcePath, auth.MustWithAuth(s.GetResource, checker, auth.RequireClientIDAndSecret)).Methods(http.MethodGet)
	r.HandleFunc(viewsPath, auth.MustWithAuth(s.GetViews, checker, auth.RequireClientIDAndSecret)).Methods(http.MethodGet)
	r.HandleFunc(flatViewsPath, auth.MustWithAuth(s.GetFlatViews, checker, auth.RequireClientIDAndSecret)).Methods(http.MethodGet)
	r.HandleFunc(viewPath, auth.MustWithAuth(s.GetView, checker, auth.RequireClientIDAndSecret)).Methods(http.MethodGet)
	r.HandleFunc(rolesPath, auth.MustWithAuth(s.GetViewRoles, checker, auth.RequireClientIDAndSecret)).Methods(http.MethodGet)
	r.HandleFunc(rolePath, auth.MustWithAuth(s.GetViewRole, checker, auth.RequireClientIDAndSecret)).Methods(http.MethodGet)
	r.HandleFunc(adaptersPath, auth.MustWithAuth(s.GetTargetAdapters, checker, auth.RequireClientIDAndSecret)).Methods(http.MethodGet)
	r.HandleFunc(translatorsPath, auth.MustWithAuth(s.GetPassportTranslators, checker, auth.RequireClientIDAndSecret)).Methods(http.MethodGet)
	r.HandleFunc(damRoleCategoriesPath, auth.MustWithAuth(s.GetDamRoleCategories, checker, auth.RequireClientIDAndSecret)).Methods(http.MethodGet)
	r.HandleFunc(testPersonasPath, auth.MustWithAuth(s.GetTestPersonas, checker, auth.RequireClientIDAndSecret)).Methods(http.MethodGet)

	// administration endpoints
	r.HandleFunc(realmPath, auth.MustWithAuth(handlerfactory.MakeHandler(s, s.realmFactory()), checker, auth.RequireAdminToken))
	r.HandleFunc(configHistoryPath, auth.MustWithAuth(s.ConfigHistory, checker, auth.RequireAdminToken)).Methods(http.MethodGet)
	r.HandleFunc(configHistoryRevisionPath, auth.MustWithAuth(s.ConfigHistoryRevision, checker, auth.RequireAdminToken)).Methods(http.MethodGet)
	r.HandleFunc(configResetPath, auth.MustWithAuth(s.ConfigReset, checker, auth.RequireAdminToken)).Methods(http.MethodGet)
	r.HandleFunc(configTestPersonasPath, auth.MustWithAuth(s.ConfigTestPersonas, checker, auth.RequireAdminToken)).Methods(http.MethodGet)
	r.HandleFunc(configPath, auth.MustWithAuth(handlerfactory.MakeHandler(s, s.configFactory()), checker, auth.RequireAdminToken))
	r.HandleFunc(configOptionsPath, auth.MustWithAuth(handlerfactory.MakeHandler(s, s.configOptionsFactory()), checker, auth.RequireAdminToken))
	r.HandleFunc(configResourcePath, auth.MustWithAuth(handlerfactory.MakeHandler(s, s.configResourceFactory()), checker, auth.RequireAdminToken))
	r.HandleFunc(configViewPath, auth.MustWithAuth(handlerfactory.MakeHandler(s, s.configViewFactory()), checker, auth.RequireAdminToken))
	r.HandleFunc(configTrustedPassportIssuerPath, auth.MustWithAuth(handlerfactory.MakeHandler(s, s.configIssuerFactory()), checker, auth.RequireAdminToken))
	r.HandleFunc(configTrustedSourcePath, auth.MustWithAuth(handlerfactory.MakeHandler(s, s.configSourceFactory()), checker, auth.RequireAdminToken))
	r.HandleFunc(configPolicyPath, auth.MustWithAuth(handlerfactory.MakeHandler(s, s.configPolicyFactory()), checker, auth.RequireAdminToken))
	r.HandleFunc(configClaimDefPath, auth.MustWithAuth(handlerfactory.MakeHandler(s, s.configClaimDefinitionFactory()), checker, auth.RequireAdminToken))
	r.HandleFunc(configServiceTemplatePath, auth.MustWithAuth(handlerfactory.MakeHandler(s, s.configServiceTemplateFactory()), checker, auth.RequireAdminToken))
	r.HandleFunc(configTestPersonaPath, auth.MustWithAuth(handlerfactory.MakeHandler(s, s.configPersonaFactory()), checker, auth.RequireAdminToken))
	r.HandleFunc(configClientPath, auth.MustWithAuth(handlerfactory.MakeHandler(s, s.configClientFactory()), checker, auth.RequireAdminToken))
	r.HandleFunc(configClientsSyncPath, auth.MustWithAuth(handlerfactory.MakeHandler(s, s.configClientsSyncFactory()), checker, auth.RequireAdminToken))

	r.HandleFunc(processesPath, auth.MustWithAuth(handlerfactory.MakeHandler(s, s.processesFactory()), checker, auth.RequireAdminToken))
	r.HandleFunc(processPath, auth.MustWithAuth(handlerfactory.MakeHandler(s, s.processFactory()), checker, auth.RequireAdminToken))

	// hydra related oidc endpoints
	r.HandleFunc(hydraLoginPath, auth.MustWithAuth(s.HydraLogin, checker, auth.RequireNone)).Methods(http.MethodGet)
	r.HandleFunc(hydraConsentPath, auth.MustWithAuth(s.HydraConsent, checker, auth.RequireNone)).Methods(http.MethodGet)

	// oidc auth callback endpoint
	r.HandleFunc(loggedInPath, auth.MustWithAuth(s.LoggedInHandler, checker, auth.RequireNone)).Methods(http.MethodGet)

	// resource token exchange endpoint
	r.HandleFunc(resourceTokensPath, auth.MustWithAuth(s.ResourceTokens, checker, auth.RequireUserToken)).Methods(http.MethodGet, http.MethodPost)
}
