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

// Package ic is identity concentrator for GA4GH Passports.
package ic

import (
	"context"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cloud.google.com/go/logging" /* copybara-comment: logging */
	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"github.com/gorilla/mux" /* copybara-comment */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"golang.org/x/oauth2" /* copybara-comment */
	"github.com/golang/protobuf/jsonpb" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
	"github.com/pborman/uuid" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/auditlogsapi" /* copybara-comment: auditlogsapi */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/auth" /* copybara-comment: auth */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/check" /* copybara-comment: check */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/cli" /* copybara-comment: cli */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/consentsapi" /* copybara-comment: consentsapi */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/faketokensapi" /* copybara-comment: faketokensapi */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/handlerfactory" /* copybara-comment: handlerfactory */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/hydraproxy" /* copybara-comment: hydraproxy */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/kms" /* copybara-comment: kms */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/oathclients" /* copybara-comment: oathclients */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/permissions" /* copybara-comment: permissions */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/scim" /* copybara-comment: scim */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/srcutil" /* copybara-comment: srcutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/strutil" /* copybara-comment: strutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/timeutil" /* copybara-comment: timeutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/tokensapi" /* copybara-comment: tokensapi */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/translator" /* copybara-comment: translator */

	glog "github.com/golang/glog" /* copybara-comment */
	lgrpcpb "google.golang.org/genproto/googleapis/logging/v2" /* copybara-comment: logging_go_grpc */
	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/ic/v1" /* copybara-comment: go_proto */
)

const (
	keyID = "visa"

	maxClaimsLength = 1900

	linkedIdentitiesMaxLifepan = time.Hour

	loginPageFile              = "pages/login.html"
	loginPageInfoFile          = "pages/ic/login_info.html"
	clientLoginPageFile        = "pages/ic/client_login.html"
	informationReleasePageFile = "pages/ic/info_release.html"
	staticDirectory            = "assets/serve/"

	serviceTitle            = "Identity Concentrator"
	loginInfoTitle          = "Data Discovery and Access Platform"
	noClientID              = ""
	noScope                 = ""
	noNonce                 = ""
	scopeOpenID             = "openid"
	matchFullScope          = false
	matchPrefixScope        = true
	generateRefreshToken    = true
	noRefreshToken          = false
	noDuration              = 0 * time.Second
	minResetClientFrequency = 2 * time.Minute
)

func defaultPath(path string) string {
	return strings.Replace(path, "{realm}", storage.DefaultRealm, -1)
}

var (
	secretParams = map[string]bool{
		"clientSecret":  true,
		"client_secret": true,
	}
	pageVariableRE = regexp.MustCompile(`\$\{[-A-Z_]*\}`)

	passportScope        = "ga4gh_passport_v1"
	ga4ghScope           = "ga4gh"
	defaultIdpScopes     = []string{"openid", "profile", "email"}
	filterAccessTokScope = map[string]bool{
		"openid":        true,
		ga4ghScope:      true,
		"identities":    true,
		"link":          true,
		"account_admin": true,
		"email":         true,
		passportScope:   true,
	}
	filterIDTokScope = map[string]bool{
		"openid":  true,
		"profile": true,
		// TODO: remove these once DDAP BFF switches to use access token.
		ga4ghScope:    true,
		passportScope: true,
		"identities":  true,
		"email":       true,
	}

	descAccountNameLength = &cpb.Descriptor{
		Label:        "Account Name Length",
		Description:  "The number of characters in a new account name generated by the identity concentrator (previously existing IC accounts are unaffected)",
		Type:         "int",
		Min:          "20", // too small loses entropy as well as a few static prefix characters are included in this number
		Max:          "32", // this will also be enforced by name check regexp
		DefaultValue: "25",
	}
	descReadOnlyMasterRealm = &cpb.Descriptor{
		Label:        "Read Only Master Realm",
		Description:  "When 'true', the master realm becomes read-only and updates to the configuration must be performed via updating a config file",
		Type:         "bool",
		DefaultValue: "false",
	}
	descWhitelistedRealms = &cpb.Descriptor{
		Label:       "Whitelisted Realms",
		Description: "By default any realm name can be created, but when this option is populated the IC will only allow realms on this list to be created (the master realm is allowed implicitly)",
		Type:        "string",
		IsList:      true,
		Regexp:      "^[\\w\\-\\.]+$",
	}
	descDefaultPassportTokenTTL = &cpb.Descriptor{
		Label:        "Default Passport Token TTL",
		Description:  "The duration of a passport TTL when no 'ttl' parameter is provided to the token minting endpoint",
		Type:         "string:duration",
		Regexp:       timeutil.DurationREStr,
		Min:          "10s",
		Max:          "180d",
		DefaultValue: "10m",
	}
	descMaxPassportTokenTTL = &cpb.Descriptor{
		Label:        "Maximum Passport Token TTL",
		Description:  "Passport requests with a 'ttl' parameter exceeding this value will be refused",
		Type:         "string:duration",
		Regexp:       timeutil.DurationREStr,
		Min:          "10s",
		Max:          "180d",
		DefaultValue: "10m",
	}
	descAuthCodeTokenTTL = &cpb.Descriptor{
		Label:        "Authorization Code TTL",
		Description:  "The valid duration of an authorization code requested from the login flow of the API (auth codes must be converted into another token before this expiry)",
		Type:         "string:duration",
		Regexp:       timeutil.DurationREStr,
		Min:          "10s",
		Max:          "60m",
		DefaultValue: "10m",
	}
	descAccessTokenTTL = &cpb.Descriptor{
		Label:        "Access Token TTL",
		Description:  "The valid duration of an access token (for authentication and authorization purposes) requested from the login flow of the API",
		Type:         "string:duration",
		Regexp:       timeutil.DurationREStr,
		Min:          "10s",
		Max:          "180d",
		DefaultValue: "1h",
	}
	descRefreshTokenTTL = &cpb.Descriptor{
		Label:        "Refresh Token TTL",
		Description:  "The valid duration of an refresh token requested from the refresh token flow of the API",
		Type:         "string:duration",
		Regexp:       timeutil.DurationREStr,
		Min:          "10s",
		Max:          "180d",
		DefaultValue: "12h",
	}
	descClaimTtlCap = &cpb.Descriptor{
		Label:        "Claim TTL Cap",
		Description:  "A maximum duration of how long individual claims can be cached and used before requiring them to be refreshed from the authority issuing the claim",
		Type:         "string:duration",
		Regexp:       timeutil.DurationREStr,
		Min:          "10s",
		Max:          "9125d",
		DefaultValue: "90d",
	}
	shortNameRE  = regexp.MustCompile(`^[A-Za-z][-_A-Za-z0-9\.]{0,30}[A-Za-z0-9]$`)
	tagField     = "tag"
	tagNameCheck = map[string]*regexp.Regexp{
		tagField: shortNameRE,
	}

	// skipURLValidationInTokenURL is for skipping URL validation for TokenUrl in format "FOO_BAR=https://...".
	skipURLValidationInTokenURL = regexp.MustCompile("^[A-Z_]*=https://.*$")
)

type Service struct {
	store                      storage.Store
	Handler                    *ServiceHandler
	httpClient                 *http.Client
	loginPageTmpl              *template.Template
	clientLoginPageTmpl        *template.Template
	infomationReleasePageTmpl  *template.Template
	startTime                  int64
	domain                     string
	serviceName                string
	accountDomain              string
	hydraAdminURL              string
	hydraPublicURL             string
	hydraPublicURLProxy        *hydraproxy.Service
	translators                sync.Map
	encryption                 kms.Encryption
	signer                     kms.Signer
	logger                     *logging.Client
	skipInformationReleasePage bool
	useHydra                   bool
	hydraSyncFreq              time.Duration
	scim                       *scim.Scim
	cliAcceptHandler           *cli.AcceptHandler
	consentDashboardURL        string
	tokenProviders             []tokensapi.TokenProvider
	auditlogs                  *auditlogsapi.AuditLogs
}

type ServiceHandler struct {
	Handler *mux.Router
	s       *Service
}

// Options contains parameters to New IC Service.
type Options struct {
	// HTTPClient: http client for making http request.
	HTTPClient *http.Client
	// Domain: domain used to host ic service.
	Domain string
	// ServiceName: name of the service including environment (example: "ic-staging")
	ServiceName string
	// AccountDomain: domain used to host service account warehouse.
	AccountDomain string
	// Store: data storage and configuration storage.
	Store storage.Store
	// Encryption: the encryption use for storing tokens safely in database.
	Encryption kms.Encryption
	// Signer: the signer use for signing jwt.
	Signer kms.Signer
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
	// HydraAdminURL: hydra admin endpoints url.
	HydraAdminURL string
	// HydraPublicURL: hydra public endpoints url.
	HydraPublicURL string
	// HydraPublicProxy: proxy for hydra public endpoint.
	HydraPublicProxy *hydraproxy.Service
	// HydraSyncFreq: how often to allow clients:sync to be called
	HydraSyncFreq time.Duration
	// ConsentDashboardURL is url to frontend consent dashboard, will replace
	// ${USER_ID} with userID.
	ConsentDashboardURL string
}

// NewService create new IC service.
func NewService(params *Options) *Service {
	r := mux.NewRouter()
	return New(r, params)
}

// New creats a new IC and registers it on r.
func New(r *mux.Router, params *Options) *Service {
	sh := &ServiceHandler{}
	loginPageTmpl, err := httputils.TemplateFromFiles(loginPageFile, loginPageInfoFile)
	if err != nil {
		glog.Exitf("cannot create template for login page: %v", err)
	}
	clientLoginPageTmpl, err := httputils.TemplateFromFiles(clientLoginPageFile)
	if err != nil {
		glog.Exitf("cannot create template for client login page: %v", err)
	}
	infomationReleasePageTmpl, err := httputils.TemplateFromFiles(informationReleasePageFile)
	if err != nil {
		glog.Exitf("cannot create template for information release page: %v", err)
	}
	syncFreq := time.Minute
	if params.HydraSyncFreq > 0 {
		syncFreq = params.HydraSyncFreq
	}

	cliAcceptHandler, err := cli.NewAcceptHandler(params.Store, params.Encryption, "/identity")
	if err != nil {
		glog.Exitf("cli.NewAcceptHandler() failed: %v", err)
	}

	s := &Service{
		store:                      params.Store,
		Handler:                    sh,
		httpClient:                 params.HTTPClient,
		loginPageTmpl:              loginPageTmpl,
		clientLoginPageTmpl:        clientLoginPageTmpl,
		infomationReleasePageTmpl:  infomationReleasePageTmpl,
		startTime:                  time.Now().Unix(),
		domain:                     params.Domain,
		serviceName:                params.ServiceName,
		accountDomain:              params.AccountDomain,
		hydraAdminURL:              params.HydraAdminURL,
		hydraPublicURL:             params.HydraPublicURL,
		hydraPublicURLProxy:        params.HydraPublicProxy,
		encryption:                 params.Encryption,
		signer:                     params.Signer,
		logger:                     params.Logger,
		skipInformationReleasePage: params.SkipInformationReleasePage,
		useHydra:                   params.UseHydra,
		hydraSyncFreq:              syncFreq,
		scim:                       scim.New(params.Store),
		cliAcceptHandler:           cliAcceptHandler,
		consentDashboardURL:        params.ConsentDashboardURL,
		auditlogs:                  auditlogsapi.NewAuditLogs(params.SDLC, params.AuditLogProject, params.ServiceName),
	}

	if s.httpClient == nil {
		s.httpClient = http.DefaultClient
	}

	if err := validateURLs(map[string]string{
		"DOMAIN as URL":         "https://" + params.Domain,
		"ACCOUNT_DOMAIN as URL": "https://" + params.AccountDomain,
	}); err != nil {
		glog.Exitf(err.Error())
	}
	exists, err := configExists(params.Store)
	if err != nil {
		glog.Exitf("cannot use storage layer: %v", err)
	}
	if !exists {
		if err = ImportConfig(params.Store, params.ServiceName, nil, true, true, true); err != nil {
			glog.Exitf("cannot import configs to service %q: %v", params.ServiceName, err)
		}
	}
	cfg, err := s.loadConfig(nil, storage.DefaultRealm)
	if err != nil {
		glog.Exitf("cannot load config: %v", err)
	}
	if err = s.checkConfigIntegrity(cfg); err != nil {
		glog.Exitf("invalid config: %v", err)
	}
	secrets, err := s.loadSecrets(nil)
	if err != nil {
		glog.Exitf("cannot load client secrets: %v", err)
	}

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, s.httpClient)
	for name, cfgIdp := range cfg.IdentityProviders {
		_, err = s.getIssuerTranslator(ctx, cfgIdp.Issuer, cfg, secrets)
		if err != nil {
			glog.Infof("failed to create translator for issuer %q: %v", name, err)
		}
	}

	if s.useHydra {
		s.tokenProviders = append(s.tokenProviders, tokensapi.NewHydraTokenManager(s.hydraAdminURL, s.getIssuerString(), s.clients))
	}

	s.syncToHydra(cfg.Clients, secrets.ClientSecrets, 30*time.Second, nil)

	sh.s = s
	sh.Handler = r
	registerHandlers(r, s)
	return s
}

func getClientID(r *http.Request) string {
	cid := httputils.QueryParam(r, "client_id")
	if len(cid) > 0 {
		return cid
	}
	return httputils.QueryParam(r, "clientId")
}

func getClientSecret(r *http.Request) string {
	cs := httputils.QueryParam(r, "client_secret")
	if len(cs) > 0 {
		return cs
	}
	return httputils.QueryParam(r, "clientSecret")
}

func getNonce(r *http.Request) (string, error) {
	n := httputils.QueryParam(r, "nonce")
	if len(n) > 0 {
		return n, nil
	}
	// TODO: should return error after front end supports nonce field.
	// return "", fmt.Errorf("request must include 'nonce'")
	return "no-nonce", nil
}

func extractState(r *http.Request) (string, error) {
	n := httputils.QueryParam(r, "state")
	if len(n) > 0 {
		return n, nil
	}
	// TODO: should return error after front end supports state field.
	// return "", fmt.Errorf("request must include 'state'")
	return "no-state", nil
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

type loginPageArgs struct {
	ProviderList   *pb.LoginPageProviders
	AssetDir       string
	ServiceTitle   string
	LoginInfoTitle string
}

func (s *Service) renderLoginPage(cfg *pb.IcConfig, pathVars map[string]string, queryParams string) (string, error) {
	list := &pb.LoginPageProviders{
		Idps:     make(map[string]*pb.LoginPageProviders_ProviderEntry),
		Personas: make(map[string]*pb.LoginPageProviders_ProviderEntry),
	}
	for name, idp := range cfg.IdentityProviders {
		list.Idps[name] = &pb.LoginPageProviders_ProviderEntry{
			Url: buildPath(loginPath, name, pathVars) + queryParams,
			Ui:  idp.Ui,
		}
	}

	args := &loginPageArgs{
		ProviderList:   list,
		AssetDir:       assetPath,
		ServiceTitle:   serviceTitle,
		LoginInfoTitle: loginInfoTitle,
	}

	sb := &strings.Builder{}
	if err := s.loginPageTmpl.Execute(sb, args); err != nil {
		return "", err
	}

	return sb.String(), nil
}

func (s *Service) idpAuthorize(in loginIn, idp *cpb.IdentityProvider, cfg *pb.IcConfig, tx storage.Tx) (*oauth2.Config, string, error) {
	stateID, err := s.buildState(in.provider, in.realm, in.challenge, tx)
	if err != nil {
		return nil, "", err
	}
	return idpConfig(idp, s.getDomainURL(), nil), stateID, nil
}

func idpConfig(idp *cpb.IdentityProvider, domainURL string, secrets *pb.IcSecrets) *oauth2.Config {
	scopes := idp.Scopes
	if scopes == nil || len(scopes) == 0 {
		scopes = defaultIdpScopes
	}
	secret := ""
	if secrets != nil {
		var ok bool
		if secret, ok = secrets.IdProviderSecrets[idp.ClientId]; !ok {
			secret = ""
		}
	}
	return &oauth2.Config{
		ClientID:     idp.ClientId,
		ClientSecret: secret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  idp.AuthorizeUrl,
			TokenURL: idp.TokenUrl,
		},
		RedirectURL: domainURL + acceptLoginPath,
		Scopes:      scopes,
	}
}

func (s *Service) buildState(idpName, realm, challenge string, tx storage.Tx) (string, error) {
	login := &cpb.LoginState{
		Provider:       idpName,
		Realm:          realm,
		LoginChallenge: challenge,
		Step:           cpb.LoginState_LOGIN,
	}

	id := uuid.New()

	err := s.store.WriteTx(storage.LoginStateDatatype, storage.DefaultRealm, storage.DefaultUser, id, storage.LatestRev, login, nil, tx)
	if err != nil {
		return "", err
	}

	return id, nil
}

func buildPath(muxPath string, name string, vars map[string]string) string {
	out := strings.Replace(muxPath, "{name}", name, -1)
	for k, v := range vars {
		out = strings.Replace(out, "{"+k+"}", v, -1)
	}
	return out
}

func buildRedirectNonOIDC(idp *cpb.IdentityProvider, idpc *oauth2.Config, state string) string {
	url, err := url.Parse(idpc.RedirectURL)
	if err != nil {
		return idpc.RedirectURL
	}
	q := url.Query()
	q.Set("state", state)
	url.RawQuery = q.Encode()
	return url.String()
}

func (s *Service) idpUsesClientLoginPage(idpName, realm string, cfg *pb.IcConfig) bool {
	idp, ok := cfg.IdentityProviders[idpName]
	if !ok {
		return false
	}
	return idp.TranslateUsing == translator.DbGapTranslatorName
}

type loginIn struct {
	provider  string
	loginHint string
	realm     string
	challenge string
	scope     []string
}

// login returns redirect and status error.
func (s *Service) login(in loginIn, cfg *pb.IcConfig) (string, error) {
	var err error

	idp, ok := cfg.IdentityProviders[in.provider]
	if !ok {
		return "", status.Errorf(codes.NotFound, "login service %q not found", in.provider)
	}

	idpc, state, err := s.idpAuthorize(in, idp, cfg, nil)
	if err != nil {
		return "", status.Errorf(codes.InvalidArgument, "%v", err)
	}
	resType := idp.ResponseType
	if len(resType) == 0 {
		resType = "code"
	}
	options := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("response_type", resType),
		oauth2.SetAuthURLParam("prompt", "login consent"),
	}
	if len(in.loginHint) > 0 {
		options = append(options, oauth2.SetAuthURLParam("login_hint", in.loginHint))
	}

	url := idpc.AuthCodeURL(state, options...)
	url = strings.Replace(url, "${CLIENT_ID}", idp.ClientId, -1)
	url = strings.Replace(url, "${REDIRECT_URI}", buildRedirectNonOIDC(idp, idpc, state), -1)
	return url, nil
}

func getStateRedirect(r *http.Request) (string, error) {
	redirect, err := url.Parse(httputils.QueryParam(r, "redirect_uri"))
	if err != nil {
		return "", fmt.Errorf("redirect_uri missing or invalid: %v", err)
	}
	q := redirect.Query()
	if clientState := httputils.QueryParam(r, "state"); len(clientState) > 0 {
		q.Set("state", clientState)
	}
	redirect.RawQuery = q.Encode()
	return redirect.String(), nil
}

func (s *Service) getAndValidateStateRedirect(r *http.Request, cfg *pb.IcConfig) (string, error) {
	redirect, err := getStateRedirect(r)
	if err != nil {
		return "", err
	}
	if len(redirect) == 0 {
		return "", fmt.Errorf("missing %q parameter", "redirect_uri")
	}
	if !matchRedirect(getClient(cfg, r), redirect) {
		return "", fmt.Errorf("redirect not registered")
	}

	return redirect, nil
}

func extractClientName(cfg *pb.IcConfig, clientID string) string {
	clientName := "the application"
	for name, cli := range cfg.Clients {
		if cli.ClientId == clientID {
			if cli.Ui != nil && len("label") > 0 {
				clientName = cli.Ui["label"]
			} else {
				clientName = name
			}
			break
		}
	}

	return clientName
}

//////////////////////////////////////////////////////////////////

func (s *Service) GetStore() storage.Store {
	return s.store
}

//////////////////////////////////////////////////////////////////

func getRealm(r *http.Request) string {
	if r == nil {
		return storage.DefaultRealm
	}
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

func (s *Service) handlerSetupNoAuth(tx storage.Tx, r *http.Request, item proto.Message) (*pb.IcConfig, int, error) {
	r.ParseForm()
	if item != nil {
		if err := jsonpb.Unmarshal(r.Body, item); err != nil && err != io.EOF {
			return nil, http.StatusBadRequest, status.Errorf(codes.InvalidArgument, "%v", err)
		}
	}
	cfg, err := s.loadConfig(tx, getRealm(r))
	if err != nil {
		return nil, http.StatusServiceUnavailable, status.Errorf(codes.Unavailable, "%v", err)
	}
	return cfg, http.StatusOK, nil
}

func (s *Service) handlerSetup(tx storage.Tx, r *http.Request, scope string, item proto.Message) (*pb.IcConfig, *pb.IcSecrets, *ga4gh.Identity, int, error) {
	cfg, st, err := s.handlerSetupNoAuth(tx, r, item)
	if err != nil {
		return nil, nil, nil, st, err
	}
	secrets, err := s.loadSecrets(tx)
	if err != nil {
		return nil, nil, nil, http.StatusServiceUnavailable, status.Errorf(codes.Unavailable, "%v", err)
	}
	c, err := auth.FromContext(r.Context())
	if err != nil {
		return nil, nil, nil, httputils.FromError(err), err
	}

	return cfg, secrets, c.ID, st, status.Errorf(httputils.RPCCode(st), "%v", err)
}

func (s *Service) accountToIdentity(ctx context.Context, acct *cpb.Account, cfg *pb.IcConfig, secrets *pb.IcSecrets) (*ga4gh.Identity, error) {
	email := acct.Properties.Subject + "@" + s.accountDomain
	id := &ga4gh.Identity{
		Subject: acct.Properties.Subject,
		Issuer:  s.getIssuerString(),
		GA4GH:   make(map[string][]ga4gh.OldClaim),
		Email:   email,
	}
	if acct.Profile != nil {
		id.Username = acct.Profile.Username
		id.Name = acct.Profile.Name
		id.GivenName = acct.Profile.GivenName
		id.FamilyName = acct.Profile.FamilyName
		id.MiddleName = acct.Profile.MiddleName
		id.Profile = acct.Profile.Profile
		id.Picture = acct.Profile.Picture
		id.ZoneInfo = acct.Profile.ZoneInfo
		id.Locale = acct.Profile.Locale
	}
	ttl := getDurationOption(cfg.Options.ClaimTtlCap, descClaimTtlCap)
	identities := make(map[string][]string)
	for _, link := range acct.ConnectedAccounts {
		subject := link.Properties.Subject
		email := link.Properties.Email
		if len(email) == 0 {
			email = subject
		}
		identities[email] = []string{"IC"}
		// TODO: consider skipping claims if idp=cfg.IdProvider[link.Provider] is missing (not <persona>) or idp.State != "ACTIVE".
		if err := s.populateLinkVisas(ctx, id, link, ttl, cfg, secrets); err != nil {
			return nil, err
		}
	}
	if len(identities) > 0 {
		id.Identities = identities
	}
	return id, nil
}

func (s *Service) loginTokenToIdentity(acTok, idTok string, idp *cpb.IdentityProvider, r *http.Request, cfg *pb.IcConfig, secrets *pb.IcSecrets) (*ga4gh.Identity, int, error) {
	t, err := s.getIssuerTranslator(r.Context(), idp.Issuer, cfg, secrets)
	if err != nil {
		return nil, http.StatusUnauthorized, err
	}

	if len(acTok) > 0 && s.idpProvidesPassports(idp) {
		tid, err := t.TranslateToken(r.Context(), acTok)
		if err != nil {
			return nil, http.StatusUnauthorized, fmt.Errorf("translating access token from issuer %q: %v", idp.Issuer, err)
		}
		if !ga4gh.HasUserinfoClaims(tid) {
			return tid, http.StatusOK, nil
		}
		id, err := translator.FetchUserinfoClaims(r.Context(), s.httpClient, tid, acTok, t)
		if err != nil {
			return nil, http.StatusUnauthorized, fmt.Errorf("fetching user info from issuer %q: %v", idp.Issuer, err)
		}
		return id, http.StatusOK, nil
	}
	if len(idTok) > 0 {
		// Assumes the login ID token is a JWT containing standard claims.
		tid, err := t.TranslateToken(r.Context(), idTok)
		if err != nil {
			return nil, http.StatusUnauthorized, fmt.Errorf("translating ID token from issuer %q: %v", idp.Issuer, err)
		}
		return tid, http.StatusOK, nil
	}
	return nil, http.StatusBadRequest, fmt.Errorf("fetching identity: the IdP is not configured to fetch passports and the IdP did not provide an ID token")
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

func (s *Service) idpProvidesPassports(idp *cpb.IdentityProvider) bool {
	if len(idp.TranslateUsing) > 0 {
		return true
	}
	for _, scope := range idp.Scopes {
		if scope == passportScope {
			return true
		}
	}
	return false
}

func (s *Service) accountLinkToVisas(ctx context.Context, acct *cpb.Account, subject, provider string, cfg *pb.IcConfig, secrets *pb.IcSecrets) ([]string, error) {
	id := &ga4gh.Identity{}
	link, _ := findLinkedAccount(acct, subject, provider)
	if link == nil {
		return []string{}, nil
	}
	ttl := getDurationOption(cfg.Options.ClaimTtlCap, descClaimTtlCap)
	if err := s.populateLinkVisas(ctx, id, link, ttl, cfg, secrets); err != nil {
		return nil, err
	}

	return id.VisaJWTs, nil
}

func linkedIdentityValue(sub, iss string) string {
	sub = url.QueryEscape(sub)
	iss = url.QueryEscape(iss)
	return fmt.Sprintf("%s,%s", sub, iss)
}

func (s *Service) addLinkedIdentities(ctx context.Context, id *ga4gh.Identity, link *cpb.ConnectedAccount, cfg *pb.IcConfig) error {
	if len(id.Subject) == 0 {
		return nil
	}

	subjectIssuers := map[string]bool{}
	now := time.Now()

	// TODO: add config option for LinkedIdentities expiry.
	exp := now.Add(linkedIdentitiesMaxLifepan).Unix()

	idp, ok := cfg.IdentityProviders[link.Provider]
	if !ok {
		// admin has removed the IdP (temp or permanent) but the linked identity is still maintained, so ignore it.
		return nil
	}

	iss := idp.Issuer

	// Add ConnectedAccount identity to linked identities.
	if len(link.Properties.Subject) != 0 {
		subjectIssuers[linkedIdentityValue(link.Properties.Subject, iss)] = true
	}

	// Add email to linked identities.
	if len(link.Properties.Email) != 0 {
		subjectIssuers[linkedIdentityValue(link.Properties.Email, iss)] = true
	}

	var linked []string
	for k := range subjectIssuers {
		linked = append(linked, k)
	}
	sort.Strings(linked)

	d := &ga4gh.VisaData{
		StdClaims: ga4gh.StdClaims{
			Subject:   id.Subject,
			Issuer:    s.getVisaIssuerString(),
			IssuedAt:  now.Unix(),
			ExpiresAt: exp,
		},
		Assertion: ga4gh.Assertion{
			Type:     ga4gh.LinkedIdentities,
			Asserted: int64(link.Refreshed),
			Value:    ga4gh.Value(strings.Join(linked, ";")),
			Source:   ga4gh.Source(s.getVisaIssuerString()),
		},
	}

	v, err := ga4gh.NewVisaFromData(ctx, d, s.visaIssuerJKU(), s.signer)
	if err != nil {
		return fmt.Errorf("ga4gh.NewVisaFromData(_) failed: %v", err)
	}

	id.VisaJWTs = append(id.VisaJWTs, string(v.JWT()))
	return nil
}

func (s *Service) populateLinkVisas(ctx context.Context, id *ga4gh.Identity, link *cpb.ConnectedAccount, ttl time.Duration, cfg *pb.IcConfig, secrets *pb.IcSecrets) error {
	passport := link.Passport
	if passport == nil {
		passport = &cpb.Passport{}
	}
	jwts, err := s.decryptEmbeddedTokens(ctx, passport.InternalEncryptedVisas)
	if err != nil {
		return err
	}

	id.VisaJWTs = append(id.VisaJWTs, jwts...)

	if err = s.addLinkedIdentities(ctx, id, link, cfg); err != nil {
		return fmt.Errorf("add linked identities to visas failed: %v", err)
	}

	return nil
}

func getScope(r *http.Request) (string, error) {
	s := httputils.QueryParam(r, "scope")
	if !hasScopes(scopeOpenID, s, matchFullScope) {
		return "", fmt.Errorf("scope must include 'openid'")
	}
	return s, nil
}

func hasScopes(want, got string, matchPrefix bool) bool {
	wanted := strings.Split(want, " ")
	gotten := strings.Split(got, " ")
	for _, w := range wanted {
		proceed := false
		for _, g := range gotten {
			if g == w || (matchPrefix && strings.HasPrefix(g, w+":")) {
				proceed = true
				break
			}
		}
		if !proceed {
			return false
		}
	}
	return true
}

func (s *Service) visaIssuerJKU() string {
	return strings.TrimSuffix(s.getDomainURL(), "/") + "/visas/jwks"
}

func (s *Service) getVisaIssuerString() string {
	return strings.TrimSuffix(s.getDomainURL(), "/") + "/visas"
}

func (s *Service) getIssuerString() string {
	if s.useHydra {
		return strings.TrimRight(s.hydraPublicURL, "/") + "/"
	}

	return ""
}

func (s *Service) getDomainURL() string {
	domain := os.Getenv("SERVICE_DOMAIN")
	if len(domain) == 0 {
		domain = s.accountDomain
	}
	if strings.HasPrefix(domain, "localhost:") {
		return "http://" + domain
	}
	return "https://" + domain
}

func getClient(cfg *pb.IcConfig, r *http.Request) *cpb.Client {
	cid := getClientID(r)
	if cid == "" {
		return nil
	}
	for _, c := range cfg.Clients {
		if c.ClientId == cid {
			return c
		}
	}
	return nil
}

func matchRedirect(client *cpb.Client, redirect string) bool {
	if client == nil || len(redirect) == 0 {
		return false
	}
	redir, err := url.Parse(redirect)
	if err != nil {
		return false
	}
	for _, v := range client.RedirectUris {
		prefix, err := url.Parse(v)
		if err == nil && redir.Host == prefix.Host && strings.HasPrefix(redir.Path, prefix.Path) && redir.Scheme == prefix.Scheme {
			return true
		}
	}
	return false
}

func (s *Service) newAccountWithLink(ctx context.Context, linkID *ga4gh.Identity, provider string, cfg *pb.IcConfig) (*cpb.Account, error) {
	now := time.Now()
	genlen := getIntOption(cfg.Options.AccountNameLength, descAccountNameLength)
	accountPrefix := "ic_"
	genlen -= len(accountPrefix)
	subject := accountPrefix + strings.Replace(uuid.New(), "-", "", -1)[:genlen]

	acct := &cpb.Account{
		Revision:          0,
		Profile:           setupAccountProfile(linkID),
		Properties:        setupAccountProperties(linkID, subject, now, now),
		ConnectedAccounts: make([]*cpb.ConnectedAccount, 0),
		State:             storage.StateActive,
		Ui:                make(map[string]string),
	}
	err := s.populateAccountVisas(ctx, acct, linkID, provider)
	if err != nil {
		return nil, err
	}
	return acct, nil
}

func (s *Service) encryptEmbeddedTokens(ctx context.Context, tokens []string) ([][]byte, error) {
	var res [][]byte
	for _, tok := range tokens {
		encrypted, err := s.encryption.Encrypt(ctx, []byte(tok), "")
		if err != nil {
			return nil, err
		}
		res = append(res, encrypted)
	}

	return res, nil
}

func (s *Service) decryptEmbeddedTokens(ctx context.Context, tokens [][]byte) ([]string, error) {
	var res []string
	for _, t := range tokens {
		tok, err := s.encryption.Decrypt(ctx, t, "")
		if err != nil {
			return nil, err
		}
		res = append(res, string(tok))
	}

	return res, nil
}

func (s *Service) populateAccountVisas(ctx context.Context, acct *cpb.Account, id *ga4gh.Identity, provider string) error {
	link, _ := findLinkedAccount(acct, id.Subject, provider)
	now := time.Now()
	if link == nil {
		link = &cpb.ConnectedAccount{
			Profile:      setupAccountProfile(id),
			Properties:   setupAccountProperties(id, id.Subject, now, now),
			Provider:     provider,
			Refreshed:    float64(now.UnixNano()) / 1e9,
			Revision:     1,
			LinkRevision: 1,
		}
		acct.ConnectedAccounts = append(acct.ConnectedAccounts, link)
	} else {
		// TODO: refresh some account profile attributes.
		link.Refreshed = float64(now.UnixNano()) / 1e9
		link.Revision++
	}
	tokens, err := s.encryptEmbeddedTokens(ctx, id.VisaJWTs)
	if err != nil {
		return err
	}
	link.Passport = &cpb.Passport{
		InternalEncryptedVisas: tokens,
	}

	return nil
}

func setupAccountProfile(id *ga4gh.Identity) *cpb.AccountProfile {
	return &cpb.AccountProfile{
		Username:   id.Username,
		Name:       id.Name,
		GivenName:  id.GivenName,
		FamilyName: id.FamilyName,
		MiddleName: id.MiddleName,
		Profile:    id.Profile,
		Picture:    id.Picture,
		ZoneInfo:   id.ZoneInfo,
		Locale:     id.Locale,
	}
}

func setupAccountProperties(id *ga4gh.Identity, subject string, created, modified time.Time) *cpb.AccountProperties {
	return &cpb.AccountProperties{
		Subject:       subject,
		Email:         id.Email,
		EmailVerified: id.EmailVerified,
		Created:       float64(created.UnixNano()) / 1e9,
		Modified:      float64(modified.UnixNano()) / 1e9,
	}
}

func visasAreEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sort.Strings(a)
	sort.Strings(b)
	if diff := cmp.Diff(a, b); diff == "" {
		return true
	}
	return false
}

func findLinkedAccount(acct *cpb.Account, subject, provider string) (*cpb.ConnectedAccount, int) {
	if acct.ConnectedAccounts == nil {
		return nil, -1
	}
	for i, link := range acct.ConnectedAccounts {
		if link.Provider == provider && link.Properties.Subject == subject {
			return link, i
		}
	}
	return nil, -1
}

func validateTranslator(translateUsing, iss string) error {
	if translateUsing == "" {
		return nil
	}
	t, ok := translator.PassportTranslators()[translateUsing]
	if !ok {
		return fmt.Errorf("invalid translator: %q", translateUsing)
	}
	validIss := false
	for _, ci := range t.CompatibleIssuers {
		if iss == ci {
			validIss = true
			break
		}
	}
	if !validIss {
		return fmt.Errorf("invalid issuer for translator %q: %q", translateUsing, iss)
	}
	return nil
}

func (s *Service) getIssuerTranslator(ctx context.Context, issuer string, cfg *pb.IcConfig, secrets *pb.IcSecrets) (translator.Translator, error) {
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
	var cfgIdp *cpb.IdentityProvider
	for _, idp := range cfg.IdentityProviders {
		if idp.Issuer == issuer {
			cfgIdp = idp
			break
		}
	}
	if cfgIdp == nil {
		return nil, fmt.Errorf("passport issuer not found %q", issuer)
	}
	t, err = s.createIssuerTranslator(ctx, cfgIdp, secrets)
	if err != nil {
		return nil, fmt.Errorf("failed to create translator for issuer %q: %v", issuer, err)
	}
	s.translators.Store(issuer, t)
	return t, err
}

func (s *Service) createIssuerTranslator(ctx context.Context, cfgIdp *cpb.IdentityProvider, secrets *pb.IcSecrets) (translator.Translator, error) {
	iss := cfgIdp.Issuer
	publicKey := ""
	k, ok := secrets.TokenKeys[iss]
	if ok {
		publicKey = k.PublicKey
	}

	selfIssuer := s.getIssuerString()

	return translator.CreateTranslator(ctx, iss, cfgIdp.TranslateUsing, cfgIdp.ClientId, publicKey, selfIssuer, s.signer)
}

func (s *Service) checkConfigIntegrity(cfg *pb.IcConfig) error {
	// Check Id Providers.
	for name, idp := range cfg.IdentityProviders {
		if err := httputils.CheckName("name", name, nil); err != nil {
			return fmt.Errorf("invalid idProvider name %q: %v", name, err)
		}
		if len(idp.Issuer) == 0 {
			return fmt.Errorf("invalid idProvider %q: missing 'issuer' field", name)
		}
		m := map[string]string{
			"issuer":       idp.Issuer,
			"authorizeUrl": idp.AuthorizeUrl,
		}
		if !skipURLValidationInTokenURL.MatchString(idp.TokenUrl) {
			m["tokenUrl"] = idp.TokenUrl
		}

		if err := validateURLs(m); err != nil {
			return err
		}
		if err := validateTranslator(idp.TranslateUsing, idp.Issuer); err != nil {
			return fmt.Errorf("identity provider %q: %v", name, err)
		}
		if _, err := check.CheckUI(idp.Ui, true); err != nil {
			return fmt.Errorf("identity provider %q: %v", name, err)
		}
	}

	// Check Clients.
	for name, client := range cfg.Clients {
		if err := oathclients.CheckClientIntegrity(name, client); err != nil {
			return err
		}
	}

	// Check Options.
	opts := makeConfigOptions(cfg.Options)
	descs := opts.ComputedDescriptors
	if err := check.CheckIntOption(opts.AccountNameLength, "accountNameLength", descs); err != nil {
		return err
	}
	if err := check.CheckStringListOption(opts.WhitelistedRealms, "whitelistedRealms", descs); err != nil {
		return err
	}
	if err := check.CheckStringOption(opts.DefaultPassportTokenTtl, "defaultPassportTokenTtl", descs); err != nil {
		return err
	}
	if err := check.CheckStringOption(opts.MaxPassportTokenTtl, "maxPassportTokenTtl", descs); err != nil {
		return err
	}
	if err := check.CheckStringOption(opts.AuthCodeTokenTtl, "authCodeTokenTtl", descs); err != nil {
		return err
	}
	if err := check.CheckStringOption(opts.AccessTokenTtl, "accessTokenTtl", descs); err != nil {
		return err
	}
	if err := check.CheckStringOption(opts.RefreshTokenTtl, "refreshTokenTtl", descs); err != nil {
		return err
	}
	if err := check.CheckStringOption(opts.ClaimTtlCap, "claimTtlCap", descs); err != nil {
		return err
	}
	dpTTL := getDurationOption(opts.DefaultPassportTokenTtl, descDefaultPassportTokenTTL)
	mpTTL := getDurationOption(opts.MaxPassportTokenTtl, descMaxPassportTokenTTL)
	if dpTTL > mpTTL {
		return fmt.Errorf("defaultPassportTtl (%s) must not be greater than maxPassportTtl (%s)", dpTTL, mpTTL)
	}

	if _, err := check.CheckUI(cfg.Ui, true); err != nil {
		return fmt.Errorf("config root: %v", err)
	}

	return nil
}

func makeConfig(cfg *pb.IcConfig) *pb.IcConfig {
	out := &pb.IcConfig{}
	proto.Merge(out, cfg)
	out.Options = makeConfigOptions(cfg.Options)
	return out
}

func makeConfigOptions(opts *pb.ConfigOptions) *pb.ConfigOptions {
	out := &pb.ConfigOptions{}
	if opts != nil {
		proto.Merge(out, opts)
	}
	out.ComputedDescriptors = map[string]*cpb.Descriptor{
		"accountNameLength":       descAccountNameLength,
		"readOnlyMasterRealm":     descReadOnlyMasterRealm,
		"whitelistedRealms":       descWhitelistedRealms,
		"defaultPassportTokenTtl": descDefaultPassportTokenTTL,
		"maxPassportTokenTtl":     descMaxPassportTokenTTL,
		"authCodeTokenTtl":        descAuthCodeTokenTTL,
		"accessTokenTtl":          descAccessTokenTTL,
		"refreshTokenTtl":         descRefreshTokenTTL,
		"claimTtlCap":             descClaimTtlCap,
	}
	return out
}

func receiveConfigOptions(opts *pb.ConfigOptions) *pb.ConfigOptions {
	out := &pb.ConfigOptions{}
	if opts != nil {
		proto.Merge(out, opts)
		out.ComputedDescriptors = nil
	}
	return out
}

func makeIdentityProvider(idp *cpb.IdentityProvider) *cpb.IdentityProvider {
	return &cpb.IdentityProvider{
		Issuer: idp.Issuer,
		Ui:     idp.Ui,
	}
}

func (s *Service) makeAccount(ctx context.Context, acct *cpb.Account, cfg *pb.IcConfig, secrets *pb.IcSecrets) *cpb.Account {
	out := &cpb.Account{}
	proto.Merge(out, acct)
	out.State = ""
	out.ConnectedAccounts = []*cpb.ConnectedAccount{}
	for _, ca := range acct.ConnectedAccounts {
		out.ConnectedAccounts = append(out.ConnectedAccounts, s.makeConnectedAccount(ctx, ca, cfg, secrets))
	}
	return out
}

func (s *Service) makeConnectedAccount(ctx context.Context, ca *cpb.ConnectedAccount, cfg *pb.IcConfig, secrets *pb.IcSecrets) *cpb.ConnectedAccount {
	out := &cpb.ConnectedAccount{}
	proto.Merge(out, ca)
	if out.Passport == nil {
		out.Passport = &cpb.Passport{}
	}
	out.Passport.InternalEncryptedVisas = nil
	jwts, err := s.decryptEmbeddedTokens(ctx, ca.Passport.InternalEncryptedVisas)
	if err == nil {
		for _, jwt := range jwts {
			visa, err := ga4gh.NewVisaFromJWT(ga4gh.VisaJWT(jwt))
			if err != nil {
				continue
			}
			out.Passport.Ga4GhAssertions = append(out.Passport.Ga4GhAssertions, visa.AssertionProto())
		}
	}
	if idp, ok := cfg.IdentityProviders[ca.Provider]; ok {
		out.ComputedIdentityProvider = makeIdentityProvider(idp)
	}
	if len(out.Provider) > 0 && out.Properties != nil && len(out.Properties.Subject) > 0 {
		out.ComputedLoginHint = makeLoginHint(out.Provider, out.Properties.Subject)
	}
	return out
}

func makeLoginHint(provider, subject string) string {
	return provider + ":" + subject
}

func (s *Service) saveNewLinkedAccount(newAcct *cpb.Account, id *ga4gh.Identity, desc string, r *http.Request, tx storage.Tx, lookup *cpb.AccountLookup) error {
	if err := s.scim.SaveAccount(nil, newAcct, desc, r, id.Subject, tx); err != nil {
		return fmt.Errorf("service dependencies not available; try again later")
	}
	rev := int64(0)
	if lookup != nil {
		rev = lookup.Revision
	}
	lookup = &cpb.AccountLookup{
		Subject:  newAcct.Properties.Subject,
		Revision: rev,
		State:    storage.StateActive,
	}
	if err := s.scim.SaveAccountLookup(lookup, getRealm(r), id.Subject, r, id, tx); err != nil {
		return fmt.Errorf("service dependencies not available; try again later")
	}
	return nil
}

func validateURLs(input map[string]string) error {
	for k, v := range input {
		if !strutil.IsURL(v) {
			return fmt.Errorf("%q value %q is not a URL", k, v)
		}
	}
	return nil
}

func getDurationOption(d string, desc *cpb.Descriptor) time.Duration {
	if desc == nil || len(desc.DefaultValue) == 0 {
		return timeutil.ParseDurationWithDefault(d, noDuration)
	}
	defVal, err := timeutil.ParseDuration(desc.DefaultValue)
	if err != nil || defVal == 0 {
		return timeutil.ParseDurationWithDefault(d, noDuration)
	}
	return timeutil.ParseDurationWithDefault(d, defVal)
}

func getIntOption(val int32, desc *cpb.Descriptor) int {
	if val != 0 || desc == nil || len(desc.DefaultValue) == 0 {
		return int(val)
	}
	defVal, _ := strconv.ParseInt(desc.DefaultValue, 10, 64)
	return int(defVal)
}

func configRevision(mod *pb.ConfigModification, cfg *pb.IcConfig) error {
	if mod != nil && mod.Revision > 0 && mod.Revision != cfg.Revision {
		return fmt.Errorf("request revision %d is out of date with current config revision %d", mod.Revision, cfg.Revision)
	}
	return nil
}

//////////////////////////////////////////////////////////////////

func (s *Service) loadConfig(tx storage.Tx, realm string) (*pb.IcConfig, error) {
	cfg := &pb.IcConfig{}
	_, err := s.realmReadTx(storage.ConfigDatatype, realm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, cfg, tx)
	if err != nil {
		return nil, fmt.Errorf("cannot load %q file: %v", storage.ConfigDatatype, err)
	}
	if err := normalizeConfig(cfg); err != nil {
		return nil, fmt.Errorf("invalid %q file: %v", storage.ConfigDatatype, err)
	}

	// glog.Infof("loaded IC config: %+v", cfg)
	return cfg, nil
}

func (s *Service) saveConfig(cfg *pb.IcConfig, desc, resType string, r *http.Request, id *ga4gh.Identity, orig, update proto.Message, modification *pb.ConfigModification, tx storage.Tx) error {
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

func (s *Service) loadSecrets(tx storage.Tx) (*pb.IcSecrets, error) {
	secrets := &pb.IcSecrets{}
	_, err := s.realmReadTx(storage.SecretsDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, secrets, tx)
	if err != nil {
		return nil, err
	}
	return secrets, nil
}

func (s *Service) saveSecrets(secrets *pb.IcSecrets, desc, resType string, r *http.Request, id *ga4gh.Identity, tx storage.Tx) error {
	secrets.Revision++
	secrets.CommitTime = float64(time.Now().UnixNano()) / 1e9
	if err := s.store.WriteTx(storage.SecretsDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, secrets.Revision, secrets, storage.MakeConfigHistory(desc, resType, secrets.Revision, secrets.CommitTime, r, id.Subject, nil, nil), tx); err != nil {
		return fmt.Errorf("service storage unavailable: %v, retry later", err)
	}
	return nil
}

func (s *Service) singleRealmReadTx(datatype, realm, user, id string, rev int64, item proto.Message, tx storage.Tx) (int, error) {
	err := s.store.ReadTx(datatype, realm, user, id, rev, item, tx)
	if err == nil {
		return http.StatusOK, nil
	}
	if storage.ErrNotFound(err) {
		if len(id) > 0 && id != storage.DefaultID {
			return http.StatusNotFound, fmt.Errorf("%s %q not found", datatype, id)
		}
		return http.StatusNotFound, fmt.Errorf("%s not found", datatype)
	}
	return http.StatusServiceUnavailable, fmt.Errorf("service storage unavailable: %v, retry later", err)
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

func isLookupActive(lookup *cpb.AccountLookup) bool {
	return lookup != nil && lookup.State == storage.StateActive
}

func normalizeConfig(cfg *pb.IcConfig) error {
	return nil
}

type damArgs struct {
	clientId     string
	clientSecret string
	persona      string
}

// ImportConfig ingests bootstrap configuration files to the IC's storage sytem.
func ImportConfig(store storage.Store, service string, cfgVars map[string]string, importConfig, importSecrets, importPermission bool) (ferr error) {
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

	glog.Infof("import IC config into data store")
	history := &cpb.HistoryEntry{
		Revision:   1,
		User:       "admin",
		CommitTime: float64(time.Now().Unix()),
		Desc:       "Inital config",
	}
	info := store.Info()
	path := info["path"]
	if service == "" || path == "" {
		return nil
	}
	fs := storage.NewFileStorage(service, path)

	if importConfig {
		cfg := &pb.IcConfig{}
		if err = fs.Read(storage.ConfigDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, cfg); err != nil {
			return err
		}
		history.Revision = cfg.Revision
		if err = storage.ReplaceContentVariables(cfg, cfgVars); err != nil {
			return fmt.Errorf("replacing variables on config file: %v", err)
		}
		if err = store.WriteTx(storage.ConfigDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, cfg.Revision, cfg, history, tx); err != nil {
			return err
		}
	}

	if importSecrets {
		secrets := &pb.IcSecrets{}
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

	return nil
}

func configExists(store storage.Store) (bool, error) {
	return store.Exists(storage.SecretsDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev)
}

// TODO: move registeration of endpoints to main package.
func registerHandlers(r *mux.Router, s *Service) {
	a := &authChecker{s: s}
	checker := &auth.Checker{
		Logger:             s.logger,
		Issuer:             s.getIssuerString(),
		Permissions:        permissions.New(s.store),
		FetchClientSecrets: a.fetchClientSecrets,
		TransformIdentity:  a.transformIdentity,
	}

	// static files
	sfs := http.StripPrefix(staticFilePath, http.FileServer(http.Dir(srcutil.Path(staticDirectory))))
	r.PathPrefix(staticFilePath).Handler(sfs)

	// oidc login flow endpoints
	r.HandleFunc(loginPath, auth.MustWithAuth(s.Login, checker, auth.RequireNone)).Methods(http.MethodGet)
	r.HandleFunc(finishLoginPath, auth.MustWithAuth(s.FinishLogin, checker, auth.RequireNone)).Methods(http.MethodGet)
	r.HandleFunc(acceptInformationReleasePath, auth.MustWithAuth(s.AcceptInformationRelease, checker, auth.RequireNone)).Methods(http.MethodPost)
	r.HandleFunc(rejectInformationReleasePath, auth.MustWithAuth(s.RejectInformationRelease, checker, auth.RequireNone)).Methods(http.MethodPost)
	r.HandleFunc(acceptLoginPath, auth.MustWithAuth(s.AcceptLogin, checker, auth.RequireNone)).Methods(http.MethodGet)

	// hydra related oidc endpoints
	r.HandleFunc(hydraLoginPath, auth.MustWithAuth(s.HydraLogin, checker, auth.RequireNone)).Methods(http.MethodGet)
	r.HandleFunc(hydraConsentPath, auth.MustWithAuth(s.HydraConsent, checker, auth.RequireNone)).Methods(http.MethodGet)

	// CLI login endpoints
	cliAuthURL := urlPathJoin(s.getDomainURL(), cliAuthPath)
	hydraAuthURL := urlPathJoin(s.hydraPublicURL, oauthAuthPath)
	hydraTokenURL := urlPathJoin(s.hydraPublicURL, oauthTokenPath)
	cliAcceptURL := urlPathJoin(s.getDomainURL(), cliAcceptPath)
	r.HandleFunc(cliRegisterPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), cli.RegisterFactory(s.GetStore(), cliRegisterPath, s.encryption, cliAuthURL, s.hydraPublicURL, hydraAuthURL, hydraTokenURL, cliAcceptURL, http.DefaultClient)), checker, auth.RequireClientIDAndSecret))
	r.HandleFunc(cliAuthPath, auth.MustWithAuth(cli.NewAuthHandler(s.GetStore()).Handle, checker, auth.RequireNone)).Methods(http.MethodGet)
	r.HandleFunc(cliAcceptPath, auth.MustWithAuth(s.cliAcceptHandler.Handle, checker, auth.RequireNone)).Methods(http.MethodGet)

	// info endpoints
	r.HandleFunc(infoPath, auth.MustWithAuth(s.Status, checker, auth.RequireNone)).Methods(http.MethodGet)
	r.HandleFunc(jwksPath, auth.MustWithAuth(s.JWKS, checker, auth.RequireNone)).Methods(http.MethodGet)

	// administration endpoints
	r.HandleFunc(realmPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), s.realmFactory()), checker, auth.RequireAdminToken))
	r.HandleFunc(configPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), s.configFactory()), checker, auth.RequireAdminToken))
	r.HandleFunc(configIdentityProvidersPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), s.configIdpFactory()), checker, auth.RequireAdminToken))
	r.HandleFunc(configClientsPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), s.configClientFactory()), checker, auth.RequireAdminToken))
	r.HandleFunc(configOptionsPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), s.configOptionsFactory()), checker, auth.RequireAdminToken))
	r.HandleFunc(configResetPath, auth.MustWithAuth(s.ConfigReset, checker, auth.RequireAdminToken)).Methods(http.MethodGet)
	r.HandleFunc(configHistoryPath, auth.MustWithAuth(s.ConfigHistory, checker, auth.RequireAdminToken)).Methods(http.MethodGet)
	r.HandleFunc(configHistoryRevisionPath, auth.MustWithAuth(s.ConfigHistoryRevision, checker, auth.RequireAdminToken)).Methods(http.MethodGet)

	// light-weight admin functions using client_id, client_secret and client scope to limit use
	r.HandleFunc(syncClientsPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), s.syncClientsFactory()), checker, auth.RequireClientIDAndSecret))

	// readonly config endpoints
	r.HandleFunc(identityProvidersPath, auth.MustWithAuth(s.IdentityProviders, checker, auth.RequireClientIDAndSecret)).Methods(http.MethodGet)
	r.HandleFunc(translatorsPath, auth.MustWithAuth(s.PassportTranslators, checker, auth.RequireClientIDAndSecret)).Methods(http.MethodGet)
	r.HandleFunc(clientPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), s.clientFactory()), checker, auth.RequireClientIDAndSecret))

	// scim service endpoints
	r.HandleFunc(scimGroupPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), scim.GroupFactory(s.GetStore(), scimGroupPath)), checker, auth.RequireAdminToken))
	r.HandleFunc(scimGroupsPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), scim.GroupsFactory(s.GetStore(), scimGroupsPath)), checker, auth.RequireAdminToken))
	r.HandleFunc(scimMePath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), scim.MeFactory(s.GetStore(), s.getDomainURL(), scimMePath)), checker, auth.RequireAccountAdminUserToken))
	r.HandleFunc(scimUserPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), scim.UserFactory(s.GetStore(), s.getDomainURL(), scimUserPath)), checker, auth.RequireAccountAdminUserToken))
	r.HandleFunc(scimUsersPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), scim.UsersFactory(s.GetStore(), s.getDomainURL(), scimUsersPath)), checker, auth.RequireAdminToken))

	// token service endpoints
	r.HandleFunc(tokensPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.store, tokensapi.ListTokensFactory(tokensPath, s.tokenProviders, s.store)), checker, auth.RequireUserToken)).Methods(http.MethodGet)
	r.HandleFunc(tokenPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.store, tokensapi.DeleteTokenFactory(tokenPath, s.tokenProviders, s.store)), checker, auth.RequireUserToken)).Methods(http.MethodDelete)

	// TODO: to remove.
	tokens := &faketokensapi.StubTokens{Token: faketokensapi.FakeToken}
	r.HandleFunc(fakeTokensPath, auth.MustWithAuth(faketokensapi.NewTokensHandler(tokens).ListTokens, checker, auth.RequireUserToken)).Methods(http.MethodGet)
	r.HandleFunc(fakeTokenPath, auth.MustWithAuth(faketokensapi.NewTokensHandler(tokens).GetToken, checker, auth.RequireUserToken)).Methods(http.MethodGet)
	r.HandleFunc(fakeTokenPath, auth.MustWithAuth(faketokensapi.NewTokensHandler(tokens).DeleteToken, checker, auth.RequireUserToken)).Methods(http.MethodDelete)

	// consents service endpoints
	consentService := s.consentService()
	r.HandleFunc(listConsentPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), consentsapi.ListConsentsFactory(consentService, listConsentPath)), checker, auth.RequireUserToken)).Methods(http.MethodGet)
	r.HandleFunc(deleteConsentPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), consentsapi.DeleteConsentFactory(consentService, deleteConsentPath)), checker, auth.RequireUserToken)).Methods(http.MethodDelete)

	// TODO: delete the mocked endpoints when complete.
	consents := &consentsapi.StubConsents{Consent: consentsapi.FakeConsent}
	r.HandleFunc(consentsPath, auth.MustWithAuth(consentsapi.NewMockConsentsHandler(consents).ListConsents, checker, auth.RequireUserToken)).Methods(http.MethodGet)
	r.HandleFunc(consentPath, auth.MustWithAuth(consentsapi.NewMockConsentsHandler(consents).DeleteConsent, checker, auth.RequireUserToken)).Methods(http.MethodDelete)

	// audit logs endpoints
	r.HandleFunc(auditlogsPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.store, auditlogsapi.ListAuditlogsPathFactory(auditlogsPath, s.auditlogs)), checker, auth.RequireUserToken)).Methods(http.MethodGet)

	// legacy endpoints
	r.HandleFunc(adminClaimsPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), s.adminClaimsFactory()), checker, auth.RequireAdminToken))
	r.HandleFunc(adminTokenMetadataPath, auth.MustWithAuth(handlerfactory.MakeHandler(s.GetStore(), s.adminTokenMetadataFactory()), checker, auth.RequireAdminToken))

	// proxy hydra oauth token endpoint
	if s.hydraPublicURLProxy != nil {
		r.HandleFunc(oauthTokenPath, s.hydraPublicURLProxy.HydraOAuthToken).Methods(http.MethodPost)
	}
}

func urlPathJoin(urlStr, pathStr string) string {
	// Niether path.Join nor url.Parse()...String() does the right thing.
	// Just append.
	s1 := strings.HasSuffix(urlStr, "/")
	s2 := strings.HasPrefix(pathStr, "/")
	if !s1 && !s2 {
		return urlStr + "/" + pathStr
	}
	if s1 && s2 {
		return urlStr + pathStr[1:]
	}
	return urlStr + pathStr
}
