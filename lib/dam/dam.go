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
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/logging" /* copybara-comment: logging */
	"github.com/gorilla/mux" /* copybara-comment */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"golang.org/x/oauth2" /* copybara-comment */
	"github.com/golang/protobuf/jsonpb" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
	"bitbucket.org/creachadair/stringset" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/adapter" /* copybara-comment: adapter */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/auditlogsapi" /* copybara-comment: auditlogsapi */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/auth" /* copybara-comment: auth */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/aws" /* copybara-comment: aws */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds" /* copybara-comment: clouds */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/consentsapi" /* copybara-comment: consentsapi */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/errutil" /* copybara-comment: errutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/faketokensapi" /* copybara-comment: faketokensapi */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/handlerfactory" /* copybara-comment: handlerfactory */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/hydraproxy" /* copybara-comment: hydraproxy */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/kms" /* copybara-comment: kms */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/lro" /* copybara-comment: lro */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/oathclients" /* copybara-comment: oathclients */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/permissions" /* copybara-comment: permissions */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/persona" /* copybara-comment: persona */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/saw" /* copybara-comment: saw */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/scim" /* copybara-comment: scim */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/srcutil" /* copybara-comment: srcutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/timeutil" /* copybara-comment: timeutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/tokensapi" /* copybara-comment: tokensapi */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/translator" /* copybara-comment: translator */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/validator" /* copybara-comment: validator */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/verifier" /* copybara-comment: verifier */

	glog "github.com/golang/glog" /* copybara-comment */
	lgrpcpb "google.golang.org/genproto/googleapis/logging/v2" /* copybara-comment: logging_go_grpc */
	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
	tgrpcpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/tokens/v1" /* copybara-comment: go_proto_grpc */
)

const (
	maxNameLength = 32
	minNameLength = 3
	clientIdLen   = 36

	noClientID          = ""
	noScope             = ""
	defaultPersonaScope = ""
	assetPath           = "/dam/static"
	staticFilePath      = "/dam/static/"
	staticDirectory     = "assets/serve/"

	informationReleasePageFile = "pages/dam/info_release.html"
)

var (
	ttlRE = regexp.MustCompile(`^[0-9]+[smhdw]$`)

	defaultTTL             = 1 * time.Hour
	defaultMaxRequestedTTL = 14 * 24 * time.Hour
	maxTTL                 = 90 * 24 * time.Hour // keep in sync with maxTTLStr
	maxTTLStr              = "90 days"           // keep in sync with maxTTL

	translators = translator.PassportTranslators()
)

type Service struct {
	adapters                   *adapter.ServiceAdapters
	roleCategories             map[string]*pb.RoleCategory
	domainURL                  string
	defaultBroker              string
	serviceName                string
	hydraAdminURL              string
	hydraPublicURL             string
	hydraPublicURLProxy        *hydraproxy.Service
	hydraSyncFreq              time.Duration
	store                      storage.Store
	warehouse                  clouds.ResourceTokenCreator
	logger                     *logging.Client
	Handler                    *ServiceHandler
	hidePolicyBasis            bool
	hideRejectDetail           bool
	httpClient                 *http.Client
	startTime                  int64
	translators                sync.Map
	visaVerifiers              sync.Map
	useHydra                   bool
	scim                       *scim.Scim
	tokens                     tgrpcpb.TokensServer
	auditlogs                  *auditlogsapi.AuditLogs
	tokenProviders             []tokensapi.TokenProvider
	signer                     kms.Signer
	encryption                 kms.Encryption
	checker                    *auth.Checker
	skipInformationReleasePage bool
	infomationReleasePageTmpl  *template.Template
	consentDashboardURL        string
	lro                        lro.LRO
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
	// AWSClient: a client for interacting with the AWS API
	AWSClient             aws.APIClient
	ServiceAccountManager *saw.AccountWarehouse
	// Logger: audit log logger
	Logger *logging.Client
	// SDLC: gRPC client to StackDriver Logging.
	SDLC lgrpcpb.LoggingServiceV2Client
	// AuditLogProject is the GCP project id where audit logs are written to.
	AuditLogProject string
	// SkipInformationReleasePage: set true if want to skip the information release page.
	SkipInformationReleasePage bool
	// UseHydra: service use hydra integrated OIDC.
	UseHydra bool
	// HydraAdminURL: hydra admin endpoints url
	HydraAdminURL string
	// HydraPublicURL: hydra public endpoints url
	HydraPublicURL string
	// HydraPublicProxy: proxy for hydra public endpoint.
	HydraPublicProxy *hydraproxy.Service
	// HydraSyncFreq: how often to allow clients:sync to be called
	HydraSyncFreq time.Duration
	// HidePolicyBasis: do not send policy basis to client
	HidePolicyBasis bool
	// HideRejectDetail: do not send rejected visas details
	HideRejectDetail bool
	// Signer: the signer use for signing jwt.
	Signer kms.Signer
	// Encryption: used to encrypt the jwt in account
	Encryption kms.Encryption
	// ConsentDashboardURL is url to frontend consent dashboard, will replace
	// ${USER_ID} with userID.
	ConsentDashboardURL string
	// LRO: the long running operation background process
	LRO lro.LRO
}

// NewService create DAM service
func NewService(params *Options) *Service {
	r := mux.NewRouter()
	return New(r, params)
}

// New creates a DAM and registers it on r.
func New(r *mux.Router, params *Options) *Service {
	var roleCat pb.DamRoleCategoriesResponse
	if err := srcutil.LoadProto("deploy/metadata/dam_roles.json", &roleCat); err != nil {
		glog.Exitf("cannot load role categories file %q: %v", "deploy/metadata/dam_roles.json", err)
	}
	syncFreq := time.Minute
	if params.HydraSyncFreq > 0 {
		syncFreq = params.HydraSyncFreq
	}

	infomationReleasePageTmpl, err := httputils.TemplateFromFiles(informationReleasePageFile)
	if err != nil {
		glog.Exitf("cannot create template for information release page: %v", err)
	}

	sh := &ServiceHandler{}
	s := &Service{
		roleCategories:             roleCat.DamRoleCategories,
		domainURL:                  params.Domain,
		defaultBroker:              params.DefaultBroker,
		serviceName:                params.ServiceName,
		store:                      params.Store,
		warehouse:                  params.Warehouse,
		logger:                     params.Logger,
		Handler:                    sh,
		hidePolicyBasis:            params.HidePolicyBasis,
		hideRejectDetail:           params.HideRejectDetail,
		httpClient:                 params.HTTPClient,
		startTime:                  time.Now().Unix(),
		skipInformationReleasePage: params.SkipInformationReleasePage,
		infomationReleasePageTmpl:  infomationReleasePageTmpl,
		consentDashboardURL:        params.ConsentDashboardURL,
		useHydra:                   params.UseHydra,
		hydraAdminURL:              params.HydraAdminURL,
		hydraPublicURL:             params.HydraPublicURL,
		hydraPublicURLProxy:        params.HydraPublicProxy,
		hydraSyncFreq:              syncFreq,
		scim:                       scim.New(params.Store),
		tokens:                     faketokensapi.NewDAMTokens(params.Store, params.ServiceAccountManager),
		auditlogs:                  auditlogsapi.NewAuditLogs(params.SDLC, params.AuditLogProject, params.ServiceName),
		signer:                     params.Signer,
		encryption:                 params.Encryption,
		lro:                        params.LRO,
	}

	if s.httpClient == nil {
		s.httpClient = http.DefaultClient
	}

	exists, err := configExists(params.Store)
	if err != nil {
		glog.Exitf("cannot use storage layer: %v", err)
	}
	if !exists {
		if err = ImportConfig(params.Store, params.ServiceName, params.Warehouse, nil, true, true, true); err != nil {
			glog.Exitf("cannot import configs to service %q: %v", params.ServiceName, err)
		}
	}
	secrets, err := s.loadSecrets(nil)
	if err != nil {
		glog.Exitf("cannot load client secrets: %v", err)
	}
	adapters, err := adapter.CreateAdapters(&adapter.Options{
		Store:     params.Store,
		Warehouse: params.Warehouse,
		AWSClient: params.AWSClient,
		Signer:    params.Signer,
	})

	if err != nil {
		glog.Exitf("cannot load adapters: %v", err)
	}
	s.adapters = adapters

	cfg, err := s.loadConfig(nil, storage.DefaultRealm)
	if err != nil {
		glog.Exitf("cannot load config: %v", err)
	}
	if stat := s.CheckIntegrity(cfg, storage.DefaultRealm, nil); stat != nil {
		glog.Exitf("config integrity error: %+v", stat.Proto())
	}
	if err = s.updateWarehouseOptions(cfg.Options, storage.DefaultRealm, nil); err != nil {
		glog.Exitf("setting service account config options failed (cannot enforce access management policies): %v", err)
	}
	if err = s.registerAllProjects(nil); err != nil {
		glog.Exitf("registation of one or more service account projects failed (cannot enforce access management policies): %v", err)
	}

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, s.httpClient)
	if tests := runTests(ctx, cfg, nil, s.ValidateCfgOpts(storage.DefaultRealm, nil)); hasTestError(tests) {
		glog.Exitf("run tests error: %v; results: %v; modification: <%v>", tests.Error, tests.TestResults, tests.Modification)
	}

	for name, cfgTpi := range cfg.TrustedIssuers {
		_, err = s.getIssuerTranslator(ctx, cfgTpi.Issuer, cfg, secrets, nil)
		if err != nil {
			glog.Infof("failed to create translator for issuer %q: %v", name, err)
		}
	}

	s.syncToHydra(cfg.Clients, secrets.ClientSecrets, 30*time.Second, nil)

	defaultBrokerURL := ""
	if broker, ok := cfg.TrustedIssuers[params.DefaultBroker]; ok {
		defaultBrokerURL = broker.Issuer
	}
	s.tokenProviders = []tokensapi.TokenProvider{
		tokensapi.NewGCPTokenManager(cfg.Options.GcpServiceAccountProject, defaultBrokerURL, params.ServiceAccountManager),
	}
	if s.useHydra {
		s.tokenProviders = append(s.tokenProviders, tokensapi.NewHydraTokenManager(s.hydraAdminURL, s.getIssuerString(), s.clients))
	}

	a := authChecker{s: s}
	checker := auth.NewChecker(s.logger, s.getIssuerString(), permissions.New(s.store), a.fetchClientSecrets, a.transformIdentity, false, nil)
	s.checker = checker

	go s.lro.Run(ctx)

	sh.s = s
	sh.Handler = r
	registerHandlers(r, s)
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

func (s *Service) handlerSetupNoAuth(tx storage.Tx, r *http.Request, item proto.Message) (*pb.DamConfig, int, error) {
	r.ParseForm()
	if item != nil {
		if err := jsonpb.Unmarshal(r.Body, item); err != nil && err != io.EOF {
			return nil, http.StatusBadRequest, err
		}
	}
	cfg, err := s.loadConfig(tx, getRealm(r))
	if err != nil {
		return nil, http.StatusServiceUnavailable, err
	}
	return cfg, http.StatusOK, nil
}

func (s *Service) handlerSetup(tx storage.Tx, r *http.Request, scope string, item proto.Message) (*pb.DamConfig, *ga4gh.Identity, int, error) {
	cfg, status, err := s.handlerSetupNoAuth(tx, r, item)
	if err != nil {
		return nil, nil, status, err
	}

	c, err := auth.FromContext(r.Context())
	if err != nil {
		return nil, nil, httputils.FromError(err), err
	}
	return cfg, c.ID, status, err
}

func (sh *ServiceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "OPTIONS" {
		httputils.WriteCorsHeaders(w)
		w.WriteHeader(http.StatusOK)
		return
	}

	// Inject http client for oauth lib.
	r = r.WithContext(context.WithValue(r.Context(), oauth2.HTTPClient, sh.s.httpClient))

	sh.Handler.ServeHTTP(w, r)
}

func checkName(name string) error {
	return httputils.CheckName("name", name, nil)
}

func (s *Service) getIssuerString() string {
	if s.useHydra {
		return strings.TrimRight(s.hydraPublicURL, "/") + "/"
	}

	return ""
}

func (s *Service) lroURI(id string) string {
	uri := strings.Replace(strings.TrimRight(s.domainURL, "/")+lroPath, "{name}", id, -1)
	return strings.Replace(uri, "{realm}", storage.DefaultRealm, -1)
}

func (s *Service) upstreamTokenToPassportIdentity(ctx context.Context, cfg *pb.DamConfig, tx storage.Tx, tok, clientID string) (*ga4gh.Identity, error) {
	id, err := ga4gh.ConvertTokenToIdentityUnsafe(tok)
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
	if ga4gh.HasUserinfoClaims(id) {
		id, err = translator.FetchUserinfoClaims(ctx, s.httpClient, id, tok, t)
		if err != nil {
			return nil, fmt.Errorf("fetching user info from issuer %q: %v", iss, err)
		}
	}

	return s.populateIdentityVisas(ctx, id, cfg)
}

func (s *Service) populateIdentityVisas(ctx context.Context, id *ga4gh.Identity, cfg *pb.DamConfig) (*ga4gh.Identity, error) {
	// Filter visas by trusted issuers.
	trusted := trustedIssuers(cfg.TrustedIssuers)
	var vs []ga4gh.VisaJWT
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

	claims, _, err := ga4gh.VisasToOldClaims(ctx, vs, s.verifyVisa)
	if err != nil {
		return nil, err
	}
	id.GA4GH = claims

	return id, nil
}

func (s *Service) verifyVisa(ctx context.Context, token, issuer, jku string) error {
	v, err := s.getVisaVerifier(ctx, issuer, jku)
	if err != nil {
		return err
	}

	return v.Verify(ctx, token, jku)
}

func (s *Service) getVisaVerifier(ctx context.Context, issuer, jku string) (*verifier.VisaVerifier, error) {
	key := issuer + " " + jku
	cached, ok := s.visaVerifiers.Load(key)
	// found verifier in cache.
	if ok {
		v, ok := cached.(*verifier.VisaVerifier)
		if !ok {
			return nil, fmt.Errorf("verifier type is wrong")
		}
		return v, nil
	}
	v, err := verifier.NewVisaVerifier(ctx, issuer, jku, "")
	if err != nil {
		return nil, err
	}
	s.visaVerifiers.Store(key, v)
	return v, nil
}

func trustedIssuers(trustedIssuers map[string]*pb.TrustedIssuer) map[string]bool {
	trusted := make(map[string]bool)
	for _, tpi := range trustedIssuers {
		trusted[tpi.Issuer] = true
	}
	return trusted
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

func testPersona(ctx context.Context, personaName string, resources []string, cfg *pb.DamConfig, vopts ValidateCfgOpts) (string, []string, []*ga4gh.RejectedVisa, error) {
	p := cfg.TestPersonas[personaName]
	id, err := persona.ToIdentity(ctx, personaName, p, defaultPersonaScope, "")
	if err != nil {
		return "INVALID", nil, nil, err
	}
	state, got, err := resolveAccessList(ctx, id, resources, nil, nil, cfg, vopts)
	if err != nil {
		return state, got, id.RejectedVisas, err
	}
	if reflect.DeepEqual(p.Access, got) || (len(p.Access) == 0 && len(got) == 0) {
		return "PASSED", got, id.RejectedVisas, nil
	}
	return "FAILED", got, id.RejectedVisas, fmt.Errorf("access does not match expectations")
}

// syncToHydra pushes the configuration of clients and secrets to Hydra.
// Use minFrequency of 0 if you always want the sync to proceed immediately after
// the last one (if it doesn't time out), or non-zero to indicate that a recent sync
// is good enough. Note there are some race conditions with several client changes
// overlapping in flight that could still have the two services be out of sync.
func (s *Service) syncToHydra(clients map[string]*cpb.Client, secrets map[string]string, minFrequency time.Duration, tx storage.Tx) (*cpb.ClientState, error) {
	if !s.useHydra {
		return nil, nil
	}
	ltx := s.store.LockTx("hydra_"+s.serviceName, minFrequency, tx)
	if ltx == nil {
		return nil, fmt.Errorf("hydra sync has completed recently or is active")
	}
	if tx == nil {
		// Is a new tx (i.e. ltx didn't override tx)
		defer ltx.Finish()
	}
	state, err := oathclients.SyncClients(s.httpClient, s.hydraAdminURL, clients, secrets)
	if err != nil {
		glog.Errorf("failed to sync hydra clients: %v", err)
		return nil, err
	}
	return state, nil
}

func resolveAccessList(ctx context.Context, id *ga4gh.Identity, resources, views, roles []string, cfg *pb.DamConfig, vopts ValidateCfgOpts) (string, []string, error) {
	var got []string
	for _, rn := range resources {
		r, ok := cfg.Resources[rn]
		if !ok {
			sort.Strings(got)
			return "FAILED", got, fmt.Errorf("resource %q not found", rn)
		}
		for vn, v := range r.Views {
			if len(views) > 0 && !stringset.Contains(views, vn) {
				continue
			}
			if len(v.Roles) == 0 {
				return "INVALID", nil, fmt.Errorf("resource %q view %q has no roles defined", rn, vn)
			}
			for rname := range v.Roles {
				if len(roles) > 0 && !stringset.Contains(roles, rname) {
					continue
				}
				if err := checkAuthorization(ctx, id, 0, rn, vn, rname, cfg, noClientID, vopts); err != nil {
					continue
				}
				got = append(got, rn+"/"+vn+"/"+rname)
			}
		}
	}
	sort.Strings(got)
	return "OK", got, nil
}

func (s *Service) makeAccessList(id *ga4gh.Identity, resources, views, roles []string, cfg *pb.DamConfig, r *http.Request, vopts ValidateCfgOpts) []string {
	// Ignore errors as the goal of makeAccessList is to show what is accessible despite any errors.
	// TODO: consider separating acceptable errors (don't halt the request) from system errors that should return an error code.
	if id == nil {
		var err error
		id, _, err = s.getPassportIdentity(cfg, nil, r)
		if err != nil {
			return nil
		}
	}
	_, got, err := resolveAccessList(r.Context(), id, resources, views, roles, cfg, vopts)
	if err != nil {
		return nil
	}
	return got
}

func checkAuthorization(ctx context.Context, id *ga4gh.Identity, ttl time.Duration, resourceName, viewName, roleName string, cfg *pb.DamConfig, client string, vopts ValidateCfgOpts) error {
	if stat := checkTrustedIssuer(id.Issuer, cfg, vopts); stat != nil {
		return errutil.WithErrorReason(errUntrustedIssuer, stat.Err())
	}
	srcRes, ok := cfg.Resources[resourceName]
	if !ok {
		return errutil.WithErrorReason(errResourceNotFound, status.Errorf(codes.NotFound, "resource %q not found", resourceName))
	}
	srcView, ok := srcRes.Views[viewName]
	if !ok {
		return errutil.WithErrorReason(errResourceViewNotFound, status.Errorf(codes.NotFound, "resource %q view %q not found", resourceName, viewName))
	}
	entries, err := resolveAggregates(srcRes, srcView, cfg, vopts.Services)
	if err != nil {
		return errutil.WithErrorReason(errResolveAggregatesFail, status.Error(codes.PermissionDenied, err.Error()))
	}
	active := false
	for _, entry := range entries {
		// Step 1: validation.
		view := entry.View
		res := entry.Res
		vRole, ok := view.Roles[roleName]
		if !ok {
			return errutil.WithErrorReason(errRoleNotAvailable, status.Errorf(codes.PermissionDenied, "unauthorized for resource %q view %q role %q (role not available on this view)", resourceName, viewName, roleName))
		}
		_, err := adapter.ResolveServiceRole(roleName, view, res, cfg)
		if err != nil {
			return errutil.WithErrorReason(errCannotResolveServiceRole, status.Errorf(codes.PermissionDenied, "unauthorized for resource %q view %q role %q (cannot resolve service role)", resourceName, viewName, roleName))
		}

		// Step 3: check visa policies.
		if len(vRole.Policies) == 0 {
			return errutil.WithErrorReason(errNoPolicyDefined, status.Errorf(codes.PermissionDenied, "unauthorized for resource %q view %q role %q (no policy defined for this view's role)", resourceName, viewName, roleName))
		}

		ctxWithTTL := context.WithValue(ctx, validator.RequestTTLInNanoFloat64, float64(ttl.Nanoseconds())/1e9)
		for _, p := range vRole.Policies {
			if p.Name == allowlistPolicyName {
				ok, err := checkAllowlist(p.Args, id, cfg, vopts)
				if err != nil {
					return errutil.WithErrorReason(errAllowlistUnavailable, status.Errorf(codes.PermissionDenied, "unauthorized for resource %q view %q role %q (allowlist unavailable): %v", resourceName, viewName, roleName, err))
				}
				if !ok {
					return errutil.WithErrorReason(errRejectedPolicy, status.Errorf(codes.PermissionDenied, "unauthorized for resource %q view %q role %q (user not on allowlist)", resourceName, viewName, roleName))
				}
				active = true
				continue
			}

			v, err := buildValidator(ctxWithTTL, p, vRole, cfg)
			if err != nil {
				return errutil.WithErrorReason(errCannotEnforcePolicies, status.Errorf(codes.PermissionDenied, "cannot enforce policies for resource %q view %q role %q: %v", resourceName, viewName, roleName, err))
			}
			ok, err = v.Validate(ctxWithTTL, id)
			if err != nil {
				// Strip internal error in case it contains any sensitive data.
				return errutil.WithErrorReason(errCannotValidateIdentity, status.Errorf(codes.PermissionDenied, "cannot validate identity (subject %q, issuer %q): internal error", id.Subject, id.Issuer))
			}
			if !ok {
				details := buildRejectedPolicy(resourceName+"/"+viewName+"/"+roleName, id.RejectedVisas, makePolicyBasis(roleName, view, res, cfg, vopts.HidePolicyBasis, vopts.Services), vopts)
				return errutil.WithErrorReason(errRejectedPolicy, withRejectedPolicy(details, status.Errorf(codes.PermissionDenied, "unauthorized for resource %q view %q role %q (policy requirements failed)", resourceName, viewName, roleName)))
			}
			active = true
		}
	}
	if !active {
		return errutil.WithErrorReason(errRoleNotEnabled, status.Errorf(codes.PermissionDenied, "unauthorized for resource %q view %q role %q (role not enabled)", resourceName, viewName, roleName))
	}
	return nil
}

func checkAllowlist(args map[string]string, id *ga4gh.Identity, cfg *pb.DamConfig, vopts ValidateCfgOpts) (bool, error) {
	if id.GA4GH == nil {
		return false, nil
	}
	users := strings.Split(args["users"], ";")
	if users[0] == "" {
		users = nil
	}
	groups := strings.Split(args["groups"], ";")
	if groups[0] == "" {
		groups = nil
	}
	for _, email := range extractEmails(id) {
		// Option 1: the allowlist item is an email address.
		for _, wl := range users {
			addr, err := mail.ParseAddress(wl)
			if err != nil {
				// Don't expose the email address to the end user, just hint at the problem being the email format.
				return false, errutil.WithErrorReason(errAllowlistUnavailable, status.Errorf(codes.PermissionDenied, "allowlist contains invalid email addresses"))
			}
			if email == addr.Address {
				return true, nil
			}
		}
		// Option 2: the allowlist item is a group.
		for _, wl := range groups {
			member, err := vopts.Scim.LoadGroupMember(wl, email, vopts.Realm, vopts.Tx)
			if err != nil {
				return false, errutil.WithErrorReason(errAllowlistUnavailable, status.Errorf(codes.PermissionDenied, "loading group %q member %q failed: %v", wl, email, err))
			}
			if member != nil {
				return true, nil
			}
		}
	}
	return false, nil
}

func extractEmails(id *ga4gh.Identity) []string {
	out := []string{}
	if id.GA4GH == nil {
		return out
	}
	for _, li := range id.GA4GH[string(ga4gh.LinkedIdentities)] {
		parts := strings.SplitN(li.Value, ",", 2)
		if len(parts) != 2 {
			continue
		}
		decoded, err := url.QueryUnescape(parts[0])
		if err != nil || !strings.Contains(decoded, "@") {
			continue
		}
		if addr, err := mail.ParseAddress(decoded); err == nil {
			out = append(out, addr.Address)
		}
	}
	return out
}

func resolveAggregates(srcRes *pb.Resource, srcView *pb.View, cfg *pb.DamConfig, tas *adapter.ServiceAdapters) ([]*adapter.AggregateView, error) {
	out := []*adapter.AggregateView{}
	st, ok := cfg.ServiceTemplates[srcView.ServiceTemplate]
	if !ok {
		return nil, fmt.Errorf("service template %q not found", srcView.ServiceTemplate)
	}
	if !isAggregate(st.ServiceName, tas) {
		out = append(out, &adapter.AggregateView{
			Index: 0,
			Res:   srcRes,
			View:  srcView,
		})
		return out, nil
	}
	serviceName := ""
	for index, item := range srcView.Items {
		vars, _, err := adapter.GetItemVariables(tas, st.ServiceName, item)
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
		if isAggregate(vst.ServiceName, tas) {
			return nil, fmt.Errorf("item %d: view uses aggregate service template %q and nesting aggregates is not permitted", index+1, vst.ServiceName)
		}
		if serviceName == "" {
			serviceName = vst.ServiceName
		} else if serviceName != vst.ServiceName {
			return nil, fmt.Errorf("item %d: service template %q uses a different target adapter %q than previous items (%q)", index+1, view.ServiceTemplate, vst.ServiceName, serviceName)
		}
		out = append(out, &adapter.AggregateView{
			Index: index,
			Res:   res,
			View:  view,
		})
	}
	return out, nil
}

func isAggregate(serviceName string, tas *adapter.ServiceAdapters) bool {
	desc, ok := tas.Descriptors[serviceName]
	if !ok {
		return false
	}
	return desc.Properties.IsAggregate
}

func configRevision(mod *pb.ConfigModification, cfg *pb.DamConfig) error {
	if mod != nil && mod.Revision > 0 && mod.Revision != cfg.Revision {
		return fmt.Errorf("request revision %d is out of date with current config revision %d", mod.Revision, cfg.Revision)
	}
	return nil
}

func viewHasRole(view *pb.View, role string) bool {
	if view.Roles == nil {
		return false
	}
	if _, ok := view.Roles[role]; ok {
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

func makeViews(r *pb.Resource, cfg *pb.DamConfig, hidePolicyBasis bool, tas *adapter.ServiceAdapters) map[string]*pb.View {
	out := make(map[string]*pb.View)
	for n, v := range r.Views {
		out[n] = makeView(n, v, r, cfg, hidePolicyBasis, tas)
	}
	return out
}

func makeView(viewName string, v *pb.View, r *pb.Resource, cfg *pb.DamConfig, hidePolicyBasis bool, tas *adapter.ServiceAdapters) *pb.View {
	return &pb.View{
		ServiceTemplate:    v.ServiceTemplate,
		Labels:             v.Labels,
		ContentTypes:       v.ContentTypes,
		ComputedInterfaces: makeViewInterfaces(v, r, cfg, tas),
		Roles:              makeViewRoles(v, r, cfg, hidePolicyBasis, tas),
		Ui:                 v.Ui,
	}
}

func makeViewInterfaces(srcView *pb.View, srcRes *pb.Resource, cfg *pb.DamConfig, tas *adapter.ServiceAdapters) map[string]*pb.Interface {
	out := make(map[string]*pb.Interface)
	entries, err := resolveAggregates(srcRes, srcView, cfg, tas)
	if err != nil {
		return out
	}
	// Map of <client_interface_name>.<interface_uri>.<label_name>.<label_value>.
	cliMap := make(map[string]map[string]map[string]string)
	for _, entry := range entries {
		st, ok := cfg.ServiceTemplates[entry.View.ServiceTemplate]
		if !ok {
			return out
		}
		for _, item := range entry.View.Items {
			vars, _, err := adapter.GetItemVariables(tas, st.ServiceName, item)
			if err != nil {
				return out
			}
			for client, uriFmt := range st.Interfaces {
				uriMap, ok := cliMap[client]
				if !ok {
					uriMap = make(map[string]map[string]string)
					cliMap[client] = uriMap
				}
				for k, v := range vars {
					uriFmt = strings.Replace(uriFmt, "${"+k+"}", v, -1)
				}
				if !hasItemVariable(uriFmt) {
					// Accept this string that has no more variables to replace.
					uriMap[uriFmt] = srcView.Labels
					if srcView.Labels == nil || srcView.Labels["platform"] == "" || len(item.Labels) > 0 {
						// Merge label lists for this item, with item.Labels overriding any view.Labels.
						labels := make(map[string]string)
						for k, v := range srcView.Labels {
							labels[k] = v
						}
						for k, v := range item.Labels {
							labels[k] = v
						}
						if desc := tas.Descriptors[st.ServiceName]; desc != nil {
							labels["platform"] = desc.Platform
						}
						uriMap[uriFmt] = labels
					}
				}
			}
		}
	}
	for k, v := range cliMap {
		vi := &pb.Interface{
			Uri: []string{},
		}
		for uri, labels := range v {
			vi.Uri = append(vi.Uri, uri)
			if len(labels) > 0 {
				vi.Labels = labels
			}
		}
		sort.Strings(vi.Uri)
		out[k] = vi
	}
	return out
}

func makeRoleCategories(view *pb.View, role string, cfg *pb.DamConfig) []string {
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

// buildRejectedPolicy combines the given information to build RejectedPolicy and the marshalled json.
func buildRejectedPolicy(requestedResource string, rejected []*ga4gh.RejectedVisa, policyBasis map[string]bool, vopts ValidateCfgOpts) *cpb.RejectedPolicy {
	rejections := len(rejected)
	if vopts.HideRejectDetail {
		rejected = nil
	}
	var basis []string
	if !vopts.HidePolicyBasis {
		for k := range policyBasis {
			basis = append(basis, k)
		}
	}
	detail := &cpb.RejectedPolicy{
		Rejections:        int32(rejections),
		PolicyBasis:       basis,
		RequestedResource: requestedResource,
	}
	for _, rv := range rejected {
		if rv == nil {
			continue
		}
		detail.RejectedVisas = append(detail.RejectedVisas, ga4gh.ToRejectedVisaProto(rv))
	}
	if rejections == 0 {
		// TODO: need a better struct or message for this case.
		detail.Message = "this passport is missing one or more visas required to meet the policy for the requested resource"
	}

	return detail
}

func makePolicyBasis(roleName string, srcView *pb.View, srcRes *pb.Resource, cfg *pb.DamConfig, hidePolicyBasis bool, tas *adapter.ServiceAdapters) map[string]bool {
	if hidePolicyBasis {
		return nil
	}
	policies := make(map[string]bool)
	entries, err := resolveAggregates(srcRes, srcView, cfg, tas)
	if err != nil {
		return nil
	}
	for _, entry := range entries {
		if role, ok := entry.View.Roles[roleName]; ok {
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

func makeViewRoles(view *pb.View, res *pb.Resource, cfg *pb.DamConfig, hidePolicyBasis bool, tas *adapter.ServiceAdapters) map[string]*pb.ViewRole {
	out := make(map[string]*pb.ViewRole)
	for rname := range view.Roles {
		out[rname] = &pb.ViewRole{
			ComputedRoleCategories: makeRoleCategories(view, rname, cfg),
			ComputedPolicyBasis:    makePolicyBasis(rname, view, res, cfg, hidePolicyBasis, tas),
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

func makeResource(name string, in *pb.Resource, cfg *pb.DamConfig, hidePolicyBasis bool, tas *adapter.ServiceAdapters) *pb.Resource {
	return &pb.Resource{
		Umbrella:    in.Umbrella,
		Views:       makeViews(in, cfg, hidePolicyBasis, tas),
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
	if out.Roles != nil {
		for _, r := range out.Roles {
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
	out.ComputedDescriptors = map[string]*cpb.Descriptor{
		"awsManagedKeysPerIamUser": {
			Label:        "AWS Managed Keys Per IAM User",
			Description:  "AWS allows up to 3 access keys of more than 12h to be active per IAM user and this option allows DAM to manage a subset of these keys",
			Type:         "int",
			Min:          "0",
			Max:          "3",
			DefaultValue: "3",
		},
		"readOnlyMasterRealm": {
			Label:        "Read Only Master Realm",
			Description:  "When 'true', the master realm becomes read-only and updates to the configuration must be performed via updating a config file",
			Type:         "bool",
			DefaultValue: "false",
		},
		"gcpManagedKeysMaxRequestedTtl": {
			Label:        "GCP Managed Keys Maximum Requested TTL",
			Description:  "The maximum TTL of a requested access token on GCP and this setting is used in conjunction with managedKeysPerAccount to set up managed access key rotation policies within DAM (disabled by default)",
			Type:         "string:duration",
			Regexp:       timeutil.DurationREStr,
			Min:          "2h",
			Max:          "180d",
			DefaultValue: timeutil.TTLString(defaultMaxRequestedTTL),
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

var (
	allowlistPolicyName = "allowlist"
	allowlistPolicy     = &pb.Policy{
		AnyOf: []*cpb.ConditionSet{{AllOf: []*cpb.Condition{}}},
		VariableDefinitions: map[string]*pb.VariableFormat{
			"users": &pb.VariableFormat{
				Type:     "split_pattern",
				Regexp:   `^[^@]+@[^@]+\.[^@]+$`,
				Optional: true,
				Ui: map[string]string{
					"label":       "User email addresses",
					"description": "a set of email addresses to grant access to",
				},
			},
			"groups": &pb.VariableFormat{
				Type:     "split_pattern",
				Regexp:   `^[A-Za-z][-_A-Za-z0-9\.]{1,30}[A-Za-z0-9]$`,
				Optional: true,
				Ui: map[string]string{
					"label":       "Group names",
					"description": "a set of group names to grant access to",
				},
			},
		},
		Ui: map[string]string{
			"label":       "Allowlist",
			"description": "Allow users and groups to be given access directly via their email addresses by verifying email properties and/or trusted LinkedIdentity visas available on user tokens",
			"infoUrl":     "https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/docs/dam/admin/config/policies.md#allowlist-policy",
			"source":      "built-in",
			"edit":        "immutable",
		},
	}

	// BuiltinPolicies contains the set of policies that are managed by DAM directly (not the administrator).
	BuiltinPolicies = map[string]*pb.Policy{
		allowlistPolicyName: allowlistPolicy,
	}
)

func normalizeConfig(cfg *pb.DamConfig) error {
	if cfg.Clients == nil {
		cfg.Clients = make(map[string]*cpb.Client)
	}
	if cfg.TestPersonas == nil {
		cfg.TestPersonas = make(map[string]*cpb.TestPersona)
	}
	for _, p := range cfg.TestPersonas {
		sort.Strings(p.Access)
	}
	if cfg.Policies == nil {
		cfg.Policies = make(map[string]*pb.Policy)
	}
	for k, v := range BuiltinPolicies {
		p := &pb.Policy{}
		proto.Merge(p, v)
		cfg.Policies[k] = p
	}
	if cfg.TrustedIssuers == nil {
		cfg.TrustedIssuers = make(map[string]*pb.TrustedIssuer)
	}
	if cfg.TrustedSources == nil {
		cfg.TrustedSources = make(map[string]*pb.TrustedSource)
	}
	if cfg.Resources == nil {
		cfg.Resources = make(map[string]*pb.Resource)
	}
	if cfg.Clients == nil {
		cfg.Clients = make(map[string]*cpb.Client)
	}
	if cfg.ServiceTemplates == nil {
		cfg.ServiceTemplates = make(map[string]*pb.ServiceTemplate)
	}
	if cfg.VisaTypes == nil {
		cfg.VisaTypes = make(map[string]*pb.VisaType)
	}
	if cfg.Options == nil {
		cfg.Options = &pb.ConfigOptions{}
	}
	if cfg.Ui == nil {
		cfg.Ui = make(map[string]string)
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

func buildValidator(ctx context.Context, vp *pb.ViewRole_ViewPolicy, viewRole *pb.ViewRole, cfg *pb.DamConfig) (*validator.Policy, error) {
	policy, ok := cfg.Policies[vp.Name]
	if !ok {
		return nil, fmt.Errorf("view policy name %q does not match any policy names", vp.Name)
	}
	return validator.BuildPolicyValidator(ctx, policy, cfg.VisaTypes, cfg.TrustedSources, vp.Args)
}

func (s *Service) saveConfig(cfg *pb.DamConfig, desc, resType string, r *http.Request, id *ga4gh.Identity, orig, update proto.Message, modification *pb.ConfigModification, tx storage.Tx) error {
	if update == nil {
		return nil
	}
	if modification != nil && modification.DryRun {
		return nil
	}
	if cfg.Policies != nil {
		// Remove built-in policies from the storage layer. These should only be maintained by the code.
		for k := range BuiltinPolicies {
			delete(cfg.Policies, k)
		}
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
		results, err := s.store.MultiReadTx(storage.ConfigDatatype, storage.AllRealms, storage.DefaultUser, storage.MatchAllIDs, nil, offset, pageSize, &pb.DamConfig{}, tx)
		if err != nil {
			return err
		}
		count := len(results.Entries)
		if count == 0 {
			break
		}
		offset += len(results.Entries)
		for _, entry := range results.Entries {
			if cfg, ok := entry.Item.(*pb.DamConfig); ok && len(cfg.Options.GcpServiceAccountProject) > 0 {
				projects[cfg.Options.GcpServiceAccountProject] = true
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
	ttl := timeutil.ParseDurationWithDefault(opts.GcpManagedKeysMaxRequestedTtl, defaultMaxRequestedTTL)
	keys := int(opts.GcpManagedKeysPerAccount)
	return s.warehouse.UpdateSettings(ttl, keys, tx)
}

// ImportConfig ingests bootstrap configuration files to the DAM's storage sytem.
func ImportConfig(store storage.Store, service string, warehouse clouds.ResourceTokenCreator, cfgVars map[string]string, importConfig, importSecrets, importPermission bool) (ferr error) {
	fs := getFileStore(store, service)
	glog.Infof("import DAM config %q into data store", fs.Info()["service"])
	tx, err := store.Tx(true)
	if err != nil {
		return err
	}
	defer func() {
		err := tx.Finish()
		if ferr == nil {
			ferr = err
		}
	}()

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
	if importConfig {
		history.Revision = cfg.Revision
		if err = storage.ReplaceContentVariables(cfg, cfgVars); err != nil {
			return fmt.Errorf("replacing variables on config file: %v", err)
		}
		if err = store.WriteTx(storage.ConfigDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, cfg.Revision, cfg, history, tx); err != nil {
			return err
		}
	}

	if importSecrets {
		secrets := &pb.DamSecrets{}
		if err = fs.Read(storage.SecretsDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, secrets); err != nil {
			return err
		}
		history.Revision = secrets.Revision
		if err = storage.ReplaceContentVariables(secrets, cfgVars); err != nil {
			return fmt.Errorf("replacing variables on secrets file: %v", err)
		}
		if err = store.WriteTx(storage.SecretsDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, secrets.Revision, secrets, history, tx); err != nil {
			return err
		}
	}

	if importPermission {
		perm := &cpb.Permissions{}
		if err = fs.Read(storage.PermissionsDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, perm); err != nil {
			return err
		}
		history.Revision = perm.Revision
		if err = storage.ReplaceContentVariables(perm, cfgVars); err != nil {
			return fmt.Errorf("replacing variables on permissions file: %v", err)
		}
		if err = store.WriteTx(storage.PermissionsDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, perm.Revision, perm, history, tx); err != nil {
			return err
		}
	}

	if warehouse == nil {
		return nil
	}
	return warehouse.RegisterAccountProject(cfg.Options.GcpServiceAccountProject, tx)
}

func configExists(store storage.Store) (bool, error) {
	return store.Exists(storage.SecretsDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev)
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

// clients fetchs oauth clients
func (s *Service) clients(tx storage.Tx) (map[string]*cpb.Client, error) {
	cfg, err := s.loadConfig(tx, storage.DefaultRealm)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "load clients failed: %v", err)
	}

	return cfg.Clients, nil
}

// TODO: move registeration of endpoints to main package.
func registerHandlers(r *mux.Router, s *Service) {
	// static files
	sfs := http.StripPrefix(staticFilePath, http.FileServer(http.Dir(srcutil.Path(staticDirectory))))
	r.PathPrefix(staticFilePath).Handler(sfs)

	// info endpoint
	r.HandleFunc(infoPath, auth.MustWithAuth(s.GetInfo, s.checker, auth.RequireNone)).Methods(http.MethodGet)
	r.HandleFunc(oidcConfiguarePath, auth.MustWithAuth(s.OidcWellKnownConfig, s.checker, auth.RequireNone)).Methods(http.MethodGet)
	r.HandleFunc(oidcJwksPath, auth.MustWithAuth(s.OidcKeys, s.checker, auth.RequireNone)).Methods(http.MethodGet)

	// readonly config endpoints
	r.HandleFunc(clientPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), s.clientFactory()), s.checker, auth.RequireClientIDAndSecret))
	r.HandleFunc(resourcesPath, auth.MustWithAuth(s.GetResources, s.checker, auth.RequireClientIDAndSecret)).Methods(http.MethodGet)
	r.HandleFunc(resourcePath, auth.MustWithAuth(s.GetResource, s.checker, auth.RequireClientIDAndSecret)).Methods(http.MethodGet)
	r.HandleFunc(viewsPath, auth.MustWithAuth(s.GetViews, s.checker, auth.RequireClientIDAndSecret)).Methods(http.MethodGet)
	r.HandleFunc(flatViewsPath, auth.MustWithAuth(s.GetFlatViews, s.checker, auth.RequireClientIDAndSecret)).Methods(http.MethodGet)
	r.HandleFunc(viewPath, auth.MustWithAuth(s.GetView, s.checker, auth.RequireClientIDAndSecret)).Methods(http.MethodGet)
	r.HandleFunc(rolesPath, auth.MustWithAuth(s.GetViewRoles, s.checker, auth.RequireClientIDAndSecret)).Methods(http.MethodGet)
	r.HandleFunc(rolePath, auth.MustWithAuth(s.GetViewRole, s.checker, auth.RequireClientIDAndSecret)).Methods(http.MethodGet)
	r.HandleFunc(servicesPath, auth.MustWithAuth(s.GetServiceDescriptors, s.checker, auth.RequireClientIDAndSecret)).Methods(http.MethodGet)
	r.HandleFunc(localeMetadataPath, auth.MustWithAuth(s.GetLocaleMetadata, s.checker, auth.RequireClientIDAndSecret)).Methods(http.MethodGet)
	r.HandleFunc(translatorsPath, auth.MustWithAuth(s.GetPassportTranslators, s.checker, auth.RequireClientIDAndSecret)).Methods(http.MethodGet)
	r.HandleFunc(damRoleCategoriesPath, auth.MustWithAuth(s.GetDamRoleCategories, s.checker, auth.RequireClientIDAndSecret)).Methods(http.MethodGet)
	r.HandleFunc(testPersonasPath, auth.MustWithAuth(s.GetTestPersonas, s.checker, auth.RequireClientIDAndSecret)).Methods(http.MethodGet)

	// light-weight admin functions using client_id, client_secret and client scope to limit use
	r.HandleFunc(syncClientsPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), s.syncClientsFactory()), s.checker, auth.RequireClientIDAndSecret))

	// administration endpoints
	r.HandleFunc(realmPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), s.realmFactory()), s.checker, auth.RequireAdminTokenClientCredential))
	r.HandleFunc(configHistoryPath, auth.MustWithAuth(s.ConfigHistory, s.checker, auth.RequireAdminTokenClientCredential)).Methods(http.MethodGet)
	r.HandleFunc(configHistoryRevisionPath, auth.MustWithAuth(s.ConfigHistoryRevision, s.checker, auth.RequireAdminTokenClientCredential)).Methods(http.MethodGet)
	r.HandleFunc(configResetPath, auth.MustWithAuth(s.ConfigReset, s.checker, auth.RequireAdminTokenClientCredential)).Methods(http.MethodGet)
	r.HandleFunc(configTestPersonasPath, auth.MustWithAuth(s.ConfigTestPersonas, s.checker, auth.RequireAdminTokenClientCredential)).Methods(http.MethodGet)
	r.HandleFunc(configPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), s.configFactory()), s.checker, auth.RequireAdminTokenClientCredential))
	r.HandleFunc(configOptionsPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), s.configOptionsFactory()), s.checker, auth.RequireAdminTokenClientCredential))
	r.HandleFunc(configResourcePath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), s.configResourceFactory()), s.checker, auth.RequireAdminTokenClientCredential))
	r.HandleFunc(configViewPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), s.configViewFactory()), s.checker, auth.RequireAdminTokenClientCredential))
	r.HandleFunc(configTrustedIssuerPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), s.configIssuerFactory()), s.checker, auth.RequireAdminTokenClientCredential))
	r.HandleFunc(configTrustedSourcePath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), s.configSourceFactory()), s.checker, auth.RequireAdminTokenClientCredential))
	r.HandleFunc(configPolicyPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), s.configPolicyFactory()), s.checker, auth.RequireAdminTokenClientCredential))
	r.HandleFunc(configVisaTypePath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), s.configVisaTypeFactory()), s.checker, auth.RequireAdminTokenClientCredential))
	r.HandleFunc(configServiceTemplatePath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), s.configServiceTemplateFactory()), s.checker, auth.RequireAdminTokenClientCredential))
	r.HandleFunc(configTestPersonaPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), s.configPersonaFactory()), s.checker, auth.RequireAdminTokenClientCredential))
	r.HandleFunc(configClientPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), s.configClientFactory()), s.checker, auth.RequireAdminTokenClientCredential))

	r.HandleFunc(processesPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), s.processesFactory()), s.checker, auth.RequireAdminTokenClientCredential))
	r.HandleFunc(processPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), s.processFactory()), s.checker, auth.RequireAdminTokenClientCredential))

	// scim service endpoints
	r.HandleFunc(scimGroupPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), scim.GroupFactory(s.GetStore(), scimGroupPath)), s.checker, auth.RequireAdminTokenClientCredential))
	r.HandleFunc(scimGroupsPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), scim.GroupsFactory(s.GetStore(), scimGroupsPath)), s.checker, auth.RequireAdminTokenClientCredential))
	r.HandleFunc(scimMePath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), scim.MeFactory(s.GetStore(), s.domainURL, scimMePath)), s.checker, auth.RequireAccountAdminUserTokenCredential))
	r.HandleFunc(scimUserPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), scim.UserFactory(s.GetStore(), s.domainURL, scimUserPath)), s.checker, auth.RequireAccountAdminUserTokenCredential))
	r.HandleFunc(scimUsersPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), scim.UsersFactory(s.GetStore(), s.domainURL, scimUsersPath)), s.checker, auth.RequireAdminTokenClientCredential))

	// hydra related oidc endpoints
	r.HandleFunc(hydraLoginPath, auth.MustWithAuth(s.HydraLogin, s.checker, auth.RequireNone)).Methods(http.MethodGet)
	r.HandleFunc(hydraConsentPath, auth.MustWithAuth(s.HydraConsent, s.checker, auth.RequireNone)).Methods(http.MethodGet)

	// information release endpoints
	r.HandleFunc(acceptInformationReleasePath, auth.MustWithAuth(s.AcceptInformationRelease, s.checker, auth.RequireNone)).Methods(http.MethodPost)
	r.HandleFunc(rejectInformationReleasePath, auth.MustWithAuth(s.RejectInformationRelease, s.checker, auth.RequireNone)).Methods(http.MethodPost)

	// oidc auth callback endpoint
	r.HandleFunc(loggedInPath, auth.MustWithAuth(s.LoggedInHandler, s.checker, auth.RequireNone)).Methods(http.MethodGet)

	// resource token exchange endpoint
	r.HandleFunc(resourceTokensPath, auth.MustWithAuth(s.ResourceTokens, s.checker, auth.RequireUserTokenClientCredential)).Methods(http.MethodGet, http.MethodPost)

	// token service endpoints
	r.HandleFunc(tokensPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.store, tokensapi.ListTokensFactory(tokensPath, s.tokenProviders, s.store)), s.checker, auth.RequireUserTokenClientCredential)).Methods(http.MethodGet)
	r.HandleFunc(tokenPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.store, tokensapi.DeleteTokenFactory(tokenPath, s.tokenProviders, s.store)), s.checker, auth.RequireUserTokenClientCredential)).Methods(http.MethodDelete)

	// consents service endpoints
	consentService := s.consentService()
	r.HandleFunc(listConsentPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), consentsapi.ListConsentsFactory(consentService, listConsentPath)), s.checker, auth.RequireUserTokenClientCredential)).Methods(http.MethodGet)
	r.HandleFunc(deleteConsentPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), consentsapi.DeleteConsentFactory(consentService, deleteConsentPath, false)), s.checker, auth.RequireUserTokenClientCredential)).Methods(http.MethodDelete)

	// audit logs endpoints
	r.HandleFunc(auditlogsPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.store, auditlogsapi.ListAuditlogsPathFactory(auditlogsPath, s.auditlogs)), s.checker, auth.RequireUserTokenClientCredential)).Methods(http.MethodGet)

	// LRO endpoints
	r.HandleFunc(lroPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), s.lroFactory()), s.checker, auth.RequireClientIDAndSecret)).Methods(http.MethodGet)

	// proxy hydra oauth token endpoint
	if s.hydraPublicURLProxy != nil {
		r.HandleFunc(oauthTokenPath, s.hydraPublicURLProxy.HydraOAuthToken).Methods(http.MethodPost)
	}
}
