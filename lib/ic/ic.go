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
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
	"github.com/gorilla/mux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/square/go-jose.v2"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/oauth2"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/hydra"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/translator"

	glog "github.com/golang/glog"
	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1"
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/ic/v1"
)

const (
	oidcPath           = "/oidc"
	oidcWellKnownPath  = oidcPath + "/.well-known"
	oidcConfiguarePath = oidcWellKnownPath + "/openid-configuration"
	oidcJwksPath       = oidcWellKnownPath + "/jwks"
	oidcUserInfoPath   = oidcPath + "/userinfo"
	keyID              = "kid"

	maxClaimsLength = 1900

	loginPageFile              = "pages/login.html"
	loginPageInfoFile          = "pages/login-info.html"
	clientLoginPageFile        = "pages/client_login.html"
	informationReleasePageFile = "pages/information_release.html"
	testPageFile               = "pages/test.html"
	tokenFlowTestPageFile      = "pages/new-flow-test.html"
	hydraICTestPageFile        = "pages/hydra-ic-test.html"
	staticDirectory            = "assets/serve/"
	version                    = "v1alpha"
	requiresAdmin              = true

	basePath         = "/identity"
	versionPath      = basePath + "/" + version
	realmPath        = versionPath + "/" + common.RealmVariable
	methodPrefix     = realmPath + "/"
	acceptLoginPath  = basePath + "/loggedin"
	assetPath        = basePath + "/static"
	staticFilePath   = assetPath + "/"
	configPathPrefix = methodPrefix + "config"

	infoPath                    = basePath
	clientPath                  = methodPrefix + "clients/{name}"
	configPath                  = methodPrefix + "config"
	configHistoryPath           = configPath + "/history"
	configHistoryRevisionPath   = configHistoryPath + "/{name}"
	configResetPath             = configPath + "/reset"
	configIdentityProvidersPath = configPath + "/identityProviders/{name}"
	configClientsPath           = configPath + "/clients/{name}"
	configOptionsPath           = configPath + "/options"

	identityProvidersPath        = methodPrefix + "identityProviders"
	translatorsPath              = methodPrefix + "passportTranslators"
	tokenPath                    = methodPrefix + "token"
	tokenMetadataPath            = methodPrefix + "token/{sub}/{jti}"
	revocationPath               = methodPrefix + "revoke"
	loginPagePath                = methodPrefix + "login"
	loginPath                    = methodPrefix + "login/{name}"
	finishLoginPrefix            = methodPrefix + "loggedin/"
	finishLoginPath              = finishLoginPrefix + "{name}"
	acceptInformationReleasePath = methodPrefix + "inforelease"

	personasPath       = methodPrefix + "personas"
	personaPath        = personasPath + "/{name}"
	accountPath        = methodPrefix + "accounts/{name}"
	accountSubjectPath = accountPath + "/subjects/{subject}"

	adminPathPrefix        = methodPrefix + "admin"
	adminClaimsPath        = adminPathPrefix + "/subjects/{name}/account/claims"
	adminTokenMetadataPath = adminPathPrefix + "/tokens"

	hydraLoginPath   = basePath + "/login"
	hydraConsentPath = basePath + "/consent"
	hydraTestPage    = basePath + "/hydra-test"

	testPath          = methodPrefix + "test"
	tokenFlowTestPath = basePath + "/new-flow-test"
	authorizePath     = methodPrefix + "authorize"

	serviceTitle         = "Identity Concentrator"
	loginInfoTitle       = "Data Discovery and Access Platform"
	noClientID           = ""
	noScope              = ""
	noNonce              = ""
	scopeOpenID          = "openid"
	matchFullScope       = false
	matchPrefixScope     = true
	generateRefreshToken = true
	noRefreshToken       = false
	noDuration           = 0 * time.Second
)

func defaultPath(path string) string {
	return strings.Replace(path, common.RealmVariable, storage.DefaultRealm, -1)
}

var (
	defaultAuthorizePath  = defaultPath(authorizePath)
	defaultTokenPath      = defaultPath(tokenPath)
	defaultRevocationPath = defaultPath(revocationPath)

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

	descAccountNameLength = &pb.ConfigOptions_Descriptor{
		Label:        "Account Name Length",
		Description:  "The number of characters in a new account name generated by the identity concentrator (previously existing IC accounts are unaffected)",
		Type:         "int",
		Min:          "20", // too small loses entropy as well as a few static prefix characters are included in this number
		Max:          "32", // this will also be enforced by name check regexp
		DefaultValue: "25",
	}
	descReadOnlyMasterRealm = &pb.ConfigOptions_Descriptor{
		Label:        "Read Only Master Realm",
		Description:  "When 'true', the master realm becomes read-only and updates to the configuration must be performed via updating a config file",
		Type:         "bool",
		DefaultValue: "false",
	}
	descWhitelistedRealms = &pb.ConfigOptions_Descriptor{
		Label:       "Whitelisted Realms",
		Description: "By default any realm name can be created, but when this option is populated the IC will only allow realms on this list to be created (the master realm is allowed implicitly)",
		Type:        "string",
		IsList:      true,
		Regexp:      "^[\\w\\-\\.]+$",
	}
	descDefaultPassportTokenTTL = &pb.ConfigOptions_Descriptor{
		Label:        "Default Passport Token TTL",
		Description:  "The duration of a passport TTL when no 'ttl' parameter is provided to the token minting endpoint",
		Type:         "string:duration",
		Regexp:       common.DurationRegexpString,
		Min:          "10s",
		Max:          "180d",
		DefaultValue: "10m",
	}
	descMaxPassportTokenTTL = &pb.ConfigOptions_Descriptor{
		Label:        "Maximum Passport Token TTL",
		Description:  "Passport requests with a 'ttl' parameter exceeding this value will be refused",
		Type:         "string:duration",
		Regexp:       common.DurationRegexpString,
		Min:          "10s",
		Max:          "180d",
		DefaultValue: "10m",
	}
	descAuthCodeTokenTTL = &pb.ConfigOptions_Descriptor{
		Label:        "Authorization Code TTL",
		Description:  "The valid duration of an authorization code requested from the login flow of the API (auth codes must be converted into another token before this expiry)",
		Type:         "string:duration",
		Regexp:       common.DurationRegexpString,
		Min:          "10s",
		Max:          "60m",
		DefaultValue: "10m",
	}
	descAccessTokenTTL = &pb.ConfigOptions_Descriptor{
		Label:        "Access Token TTL",
		Description:  "The valid duration of an access token (for authentication and authorization purposes) requested from the login flow of the API",
		Type:         "string:duration",
		Regexp:       common.DurationRegexpString,
		Min:          "10s",
		Max:          "180d",
		DefaultValue: "1h",
	}
	descRefreshTokenTTL = &pb.ConfigOptions_Descriptor{
		Label:        "Refresh Token TTL",
		Description:  "The valid duration of an refresh token requested from the refresh token flow of the API",
		Type:         "string:duration",
		Regexp:       common.DurationRegexpString,
		Min:          "10s",
		Max:          "180d",
		DefaultValue: "12h",
	}
	descClaimTtlCap = &pb.ConfigOptions_Descriptor{
		Label:        "Claim TTL Cap",
		Description:  "A maximum duration of how long individual claims can be cached and used before requiring them to be refreshed from the authority issuing the claim",
		Type:         "string:duration",
		Regexp:       common.DurationRegexpString,
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

	importDefault = os.Getenv("IMPORT")
)

type Service struct {
	store                 storage.Store
	Handler               *ServiceHandler
	ctx                   context.Context
	httpClient            *http.Client
	loginPage             string
	clientLoginPage       string
	infomationReleasePage string
	testPage              string
	tokenFlowTestPage     string
	hydraTestPage         string
	startTime             int64
	permissions           *common.Permissions
	domain                string
	accountDomain         string
	hydraAdminURL         string
	translators           sync.Map
	encryption            Encryption
	useHydra              bool
}

type ServiceHandler struct {
	Handler *mux.Router
	s       *Service
}

// Encryption abstracts a encryption service for storing visa.
type Encryption interface {
	Encrypt(ctx context.Context, data []byte, additionalAuthData string) ([]byte, error)
	Decrypt(ctx context.Context, encrypted []byte, additionalAuthData string) ([]byte, error)
}

// NewService create new IC service.
// - domain: domain used to host ic service
// - accountDomain: domain used to host service account warehouse
// - hydraAdminURL: hydra admin endpoints url
// - store: data storage and configuration storage
// - encryption: the encryption use for storing tokens safely in database
func NewService(ctx context.Context, domain, accountDomain, hydraAdminURL string, store storage.Store, encryption Encryption, useHydra bool) *Service {
	sh := &ServiceHandler{}
	lp, err := common.LoadFile(loginPageFile)
	if err != nil {
		glog.Fatalf("cannot load login page: %v", err)
	}
	lpi, err := common.LoadFile(loginPageInfoFile)
	if err != nil {
		glog.Fatalf("cannot load login page info %q: %v", loginPageInfoFile, err)
	}
	lp = strings.Replace(lp, "${LOGIN_INFO_HTML}", lpi, -1)
	clp, err := common.LoadFile(clientLoginPageFile)
	if err != nil {
		glog.Fatalf("cannot load client login page: %v", err)
	}
	irp, err := common.LoadFile(informationReleasePageFile)
	if err != nil {
		glog.Fatalf("cannot load information release page: %v", err)
	}
	tp, err := common.LoadFile(testPageFile)
	if err != nil {
		glog.Fatalf("cannot load test page: %v", err)
	}
	tfp, err := common.LoadFile(tokenFlowTestPageFile)
	if err != nil {
		glog.Fatalf("cannot load token flow test page: %v", err)
	}
	htp, err := common.LoadFile(hydraICTestPageFile)
	if err != nil {
		glog.Fatalf("cannot load hydra test page: %v", err)
	}

	perms, err := common.LoadPermissions(store)
	if err != nil {
		glog.Fatalf("cannot load permissions:%v", err)
	}
	s := &Service{
		store:                 store,
		Handler:               sh,
		ctx:                   ctx,
		httpClient:            http.DefaultClient,
		loginPage:             lp,
		clientLoginPage:       clp,
		infomationReleasePage: irp,
		testPage:              tp,
		tokenFlowTestPage:     tfp,
		hydraTestPage:         htp,
		startTime:             time.Now().Unix(),
		permissions:           perms,
		domain:                domain,
		accountDomain:         accountDomain,
		hydraAdminURL:         hydraAdminURL,
		encryption:            encryption,
		useHydra:              useHydra,
	}

	if err := validateURLs(map[string]string{
		"DOMAIN as URL":         "https://" + domain,
		"ACCOUNT_DOMAIN as URL": "https://" + accountDomain,
	}); err != nil {
		glog.Fatalf(err.Error())
	}
	if err = s.ImportFiles(importDefault); err != nil {
		glog.Fatalf("cannot initialize storage: %v", err)
	}
	cfg, err := s.loadConfig(nil, storage.DefaultRealm)
	if err != nil {
		glog.Fatalf("cannot load config: %v", err)
	}
	if err = s.checkConfigIntegrity(cfg); err != nil {
		glog.Fatalf("invalid config: %v", err)
	}
	secrets, err := s.loadSecrets(nil)
	if err != nil {
		glog.Fatalf("cannot load client secrets: %v", err)
	}

	for name, cfgIdp := range cfg.IdentityProviders {
		_, err = s.getIssuerTranslator(s.ctx, cfgIdp.Issuer, cfg, secrets)
		if err != nil {
			glog.Infof("failed to create translator for issuer %q: %v", name, err)
		}
	}

	sh.s = s
	sh.Handler = s.buildHandlerMux()
	return s
}

func getClientID(r *http.Request) string {
	cid := common.GetParam(r, "client_id")
	if len(cid) > 0 {
		return cid
	}
	return common.GetParam(r, "clientId")
}

func getClientSecret(r *http.Request) string {
	cs := common.GetParam(r, "client_secret")
	if len(cs) > 0 {
		return cs
	}
	return common.GetParam(r, "clientSecret")
}

func getNonce(r *http.Request) (string, error) {
	n := common.GetParam(r, "nonce")
	if len(n) > 0 {
		return n, nil
	}
	// TODO: should return error after front end supports nonce field.
	// return "", fmt.Errorf("request must include 'nonce'")
	return "no-nonce", nil
}

func isUserInfo(r *http.Request) bool {
	path := common.RequestAbstractPath(r)
	return path == oidcUserInfoPath
}

func extractState(r *http.Request) (string, error) {
	n := common.GetParam(r, "state")
	if len(n) > 0 {
		return n, nil
	}
	// TODO: should return error after front end supports state field.
	// return "", fmt.Errorf("request must include 'state'")
	return "no-state", nil
}

func (sh *ServiceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "OPTIONS" {
		common.AddCorsHeaders(w)
		w.WriteHeader(http.StatusOK)
		return
	}
	r.ParseForm()
	// Allow some requests to proceed without client IDs and/or secrets.
	path := common.RequestAbstractPath(r)
	if path == infoPath || strings.HasPrefix(path, staticFilePath) || strings.HasPrefix(path, testPath) || strings.HasPrefix(path, tokenFlowTestPath) || strings.HasPrefix(path, acceptLoginPath) || path == acceptInformationReleasePath || strings.HasPrefix(path, oidcPath) || path == hydraLoginPath || path == hydraConsentPath || path == hydraTestPage {
		sh.Handler.ServeHTTP(w, r)
		return
	}

	// OAuth2 client logic will include in hydra.
	// TODO: remove unused endpoints.
	if sh.s.useHydra {
		sh.Handler.ServeHTTP(w, r)
		return
	}

	if status, err := sh.s.verifyClient(path, r); err != nil {
		http.Error(w, err.Error(), status)
		return
	}
	sh.Handler.ServeHTTP(w, r)
}

func (s *Service) verifyClient(abstractPath string, r *http.Request) (int, error) {
	cid := getClientID(r)
	if len(cid) == 0 {
		return http.StatusUnauthorized, fmt.Errorf("authorization requires a client ID")
	}
	cliOnly := isClientOnly(abstractPath)
	cs := getClientSecret(r)
	if len(cs) == 0 && !cliOnly {
		return http.StatusUnauthorized, fmt.Errorf("authorization requires a client secret")
	}

	secrets, err := s.loadSecrets(nil)
	if err != nil {
		return http.StatusServiceUnavailable, fmt.Errorf("configuration unavailable")
	}

	if secret, ok := secrets.ClientSecrets[cid]; !ok || (secret != cs && !cliOnly) {
		return http.StatusUnauthorized, fmt.Errorf("unauthorized client")
	}
	return http.StatusOK, nil
}

func isClientOnly(path string) bool {
	return strings.HasPrefix(path, authorizePath) || strings.HasPrefix(path, loginPagePath) || strings.HasPrefix(path, finishLoginPrefix) || strings.HasPrefix(path, personasPath) || strings.HasPrefix(path, clientPath) || strings.HasPrefix(path, translatorsPath) || strings.HasPrefix(path, identityProvidersPath)
}

func (s *Service) buildHandlerMux() *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc(infoPath, s.GetInfo)
	r.HandleFunc(realmPath, common.MakeHandler(s, s.realmFactory()))
	r.HandleFunc(clientPath, common.MakeHandler(s, s.clientFactory()))
	r.HandleFunc(configPath, common.MakeHandler(s, s.configFactory()))
	r.HandleFunc(configHistoryPath, s.ConfigHistory)
	r.HandleFunc(configHistoryRevisionPath, s.ConfigHistoryRevision)
	r.HandleFunc(configResetPath, s.ConfigReset)
	r.HandleFunc(configIdentityProvidersPath, common.MakeHandler(s, s.configIdpFactory()))
	r.HandleFunc(configClientsPath, common.MakeHandler(s, s.configClientFactory()))
	r.HandleFunc(configOptionsPath, common.MakeHandler(s, s.configOptionsFactory()))
	r.HandleFunc(identityProvidersPath, s.IdentityProviders)
	r.HandleFunc(translatorsPath, s.PassportTranslators)
	r.HandleFunc(tokenPath, s.Token)
	r.HandleFunc(tokenMetadataPath, common.MakeHandler(s, s.tokenMetadataFactory()))
	r.HandleFunc(adminTokenMetadataPath, common.MakeHandler(s, s.adminTokenMetadataFactory()))
	r.HandleFunc(revocationPath, s.Revocation)
	r.HandleFunc(loginPagePath, s.LoginPage)
	r.HandleFunc(loginPath, s.Login)
	r.HandleFunc(acceptLoginPath, s.AcceptLogin)
	r.HandleFunc(finishLoginPath, s.FinishLogin)
	r.HandleFunc(acceptInformationReleasePath, s.acceptInformationRelease).Methods("GET")
	r.HandleFunc(testPath, s.Test)
	r.HandleFunc(tokenFlowTestPath, s.TokenFlowTest)
	r.HandleFunc(authorizePath, s.Authorize)
	r.HandleFunc(accountPath, common.MakeHandler(s, s.accountFactory()))
	r.HandleFunc(accountSubjectPath, common.MakeHandler(s, s.accountSubjectFactory()))
	r.HandleFunc(adminClaimsPath, common.MakeHandler(s, s.adminClaimsFactory()))

	r.HandleFunc(oidcConfiguarePath, s.OidcWellKnownConfig).Methods("GET")
	r.HandleFunc(oidcJwksPath, s.OidcKeys).Methods("GET")
	r.HandleFunc(oidcUserInfoPath, s.OidcUserInfo).Methods("GET", "POST")

	r.HandleFunc(hydraLoginPath, s.HydraLogin).Methods(http.MethodGet)
	r.HandleFunc(hydraConsentPath, s.HydraConsent).Methods(http.MethodGet)
	r.HandleFunc(hydraTestPage, s.HydraTestPage).Methods(http.MethodGet)

	r.HandleFunc("/tokens", NewTokensHandler(&stubTokens{}).ListTokens).Methods(http.MethodGet)
	r.HandleFunc("/tokens/", NewTokensHandler(&stubTokens{}).GetToken).Methods(http.MethodGet)
	r.HandleFunc("/tokens/", NewTokensHandler(&stubTokens{}).DeleteToken).Methods(http.MethodDelete)

	sfs := http.StripPrefix(staticFilePath, http.FileServer(http.Dir(filepath.Join(storage.ProjectRoot, staticDirectory))))
	r.PathPrefix(staticFilePath).Handler(sfs)
	return r
}

//////////////////////////////////////////////////////////////////

func (s *Service) GetInfo(w http.ResponseWriter, r *http.Request) {
	out := &pb.GetInfoResponse{
		Name:      "Identity Concentrator",
		Versions:  []string{version},
		StartTime: s.startTime,
	}
	if _, err := s.verifyClient(common.RequestAbstractPath(r), r); err == nil {
		out.Modules = []string{}
	}

	realm := common.GetParamOrDefault(r, "realm", storage.DefaultRealm)
	if cfg, err := s.loadConfig(nil, realm); err == nil {
		out.Ui = cfg.Ui
	}
	common.SendResponse(out, w)
}

// ConfigHistory implements the HistoryConfig RPC method.
func (s *Service) ConfigHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request method not supported: %q", r.Method), w)
		return
	}
	// TODO: consider requiring an "admin" scope (modify all admin handlerSetup calls).
	_, _, _, status, err := s.handlerSetup(nil, requiresAdmin, r, noScope, nil)
	if err != nil {
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
	_, _, _, status, err := s.handlerSetup(nil, requiresAdmin, r, noScope, nil)
	if err != nil {
		common.HandleError(status, err, w)
		return
	}
	cfg := &pb.IcConfig{}
	if status, err := s.realmReadTx(storage.ConfigDatatype, getRealm(r), storage.DefaultUser, storage.DefaultID, rev, cfg, nil); err != nil {
		common.HandleError(status, err, w)
		return
	}
	common.SendResponse(cfg, w)
}

// ConfigReset implements the corresponding method in the IC API.
func (s *Service) ConfigReset(w http.ResponseWriter, r *http.Request) {
	// TODO: probably should not be a GET, but handy for now on a browser...
	if r.Method != http.MethodGet {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request method not supported: %q", r.Method), w)
		return
	}
	_, _, _, status, err := s.handlerSetup(nil, requiresAdmin, r, noScope, nil)
	if err != nil {
		common.HandleError(status, err, w)
		return
	}
	if err = s.store.Wipe(storage.WipeAllRealms); err != nil {
		common.HandleError(http.StatusInternalServerError, err, w)
		return
	}
	if err = s.ImportFiles(importDefault); err != nil {
		common.HandleError(http.StatusInternalServerError, err, w)
		return
	}
}

func (s *Service) IdentityProviders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request method not supported: %q", r.Method), w)
		return
	}
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	resp := &pb.GetIdentityProvidersResponse{
		IdentityProviders: make(map[string]*pb.IdentityProvider),
	}
	for name, idp := range cfg.IdentityProviders {
		resp.IdentityProviders[name] = makeIdentityProvider(idp)
	}
	common.SendResponse(resp, w)
}

// PassportTranslators implements the corresponding REST API endpoint.
func (s *Service) PassportTranslators(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request method not supported: %q", r.Method), w)
		return
	}
	out := translator.GetPassportTranslators()
	common.SendResponse(out, w)
}

func (s *Service) Token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request method not supported: %q", r.Method), w)
		return
	}
	typ := common.GetParam(r, "grant_type")
	if typ != "authorization_code" && typ != "refresh_token" {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("grant type not supported: %q", typ), w)
		return
	}
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}

	secrets, err := s.loadSecrets(nil)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}

	var identity *ga4gh.Identity
	var status int
	genRefresh := generateRefreshToken
	if typ == "authorization_code" {
		redirect := common.GetParam(r, "redirect_uri")
		if len(redirect) == 0 {
			common.HandleError(http.StatusBadRequest, fmt.Errorf("redirect not specified"), w)
			return
		}
		// TODO: match redirect_uri with the one in the auth code.
		if !matchRedirect(getClient(cfg, r), redirect) {
			common.HandleError(http.StatusBadRequest, fmt.Errorf("redirect not registered"), w)
			return
		}
		code, status, err := getAuthCode(r)
		if err != nil {
			common.HandleError(status, err, w)
			return
		}
		identity, status, err = s.authCodeToIdentity(code, r, cfg, secrets, nil)
		if err != nil {
			common.HandleError(status, err, w)
			return
		}
	} else {
		genRefresh = noRefreshToken
		identity, status, err = s.refreshTokenToIdentity(common.GetParam(r, "refresh_token"), r, cfg, secrets, nil)
		if err != nil {
			common.HandleError(status, err, w)
			return
		}
		if !hasScopes("refresh", identity.Scope, matchFullScope) {
			common.HandleError(http.StatusBadRequest, fmt.Errorf("token provided is not a refresh_token"), w)
			return
		}
	}
	resp, err := s.createTokens(identity, genRefresh, r, cfg, nil)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	common.SendResponse(resp, w)
}

// Revocation implements the /revoke endpoint for revoking tokens.
func (s *Service) Revocation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request method not supported: %q", r.Method), w)
		return
	}
	tx, err := s.GetStore().Tx(true)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, fmt.Errorf("service dependencies not available; try again later"), w)
		return
	}
	defer tx.Finish()

	cfg, err := s.loadConfig(tx, getRealm(r))
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}

	secrets, err := s.loadSecrets(tx)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}

	// Parse the token to be revoked.
	// TODO: remove the RevocationRequest proto fields as GetParam() is needed instead.
	inputToken := common.GetParam(r, "token")
	if len(inputToken) == 0 {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("missing token parameter"), w)
		return
	}
	identity, status, err := s.refreshTokenToIdentity(inputToken, r, cfg, secrets, tx)
	if err != nil {
		common.HandleError(status, err, w)
		return
	}
	if !hasScopes("refresh", identity.Scope, matchFullScope) {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("token provided is not a refresh token"), w)
		return
	}

	// Delete the token from storage.
	if err := s.store.DeleteTx(storage.TokensDatatype, getRealm(r), identity.Subject, identity.ID, storage.LatestRev, tx); err != nil {
		common.HandleError(http.StatusInternalServerError, fmt.Errorf("failed to revoke token: %v", err), w)
	}
	return
}

func (s *Service) LoginPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request method not supported: %q", r.Method), w)
		return
	}

	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}

	redirect, err := s.getAndValidateStateRedirect(r, cfg)
	if err != nil {
		common.HandleError(http.StatusBadRequest, err, w)
	}

	scope, err := getScope(r)
	if err != nil {
		common.HandleError(http.StatusBadRequest, err, w)
		return
	}

	state, err := extractState(r)
	if err != nil {
		common.HandleError(http.StatusBadRequest, err, w)
		return
	}

	nonce, err := getNonce(r)
	if err != nil {
		common.HandleError(http.StatusBadRequest, err, w)
		return
	}

	params := "?client_id=" + getClientID(r) + "&redirect_uri=" + url.QueryEscape(redirect) + "&state=" + url.QueryEscape(state) + "&nonce=" + url.QueryEscape(nonce)
	if len(scope) > 0 {
		params += "&scope=" + url.QueryEscape(scope)
	}
	vars := mux.Vars(r)

	page, err := s.renderLoginPage(cfg, vars, params)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
	}
	common.SendHTML(page, w)
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

	ma := jsonpb.Marshaler{}
	json, err := ma.MarshalToString(list)
	if err != nil {
		return "", err
	}
	page := strings.Replace(s.loginPage, "${PROVIDER_LIST}", json, -1)
	page = strings.Replace(page, "${ASSET_DIR}", assetPath, -1)
	page = strings.Replace(page, "${SERVICE_TITLE}", serviceTitle, -1)
	page = strings.Replace(page, "${LOGIN_INFO_TITLE}", loginInfoTitle, -1)
	return page, nil
}

func (s *Service) idpAuthorize(idpName string, idp *pb.IdentityProvider, redirect string, r *http.Request, cfg *pb.IcConfig, tx storage.Tx) (*oauth2.Config, string, error) {
	scope, err := getScope(r)
	if err != nil {
		return nil, "", err
	}

	// TODO: Remove after all idp use passport visa.
	if idp.UsePassportVisa {
		scope = strings.Join(idp.Scopes, " ")
	}

	state := ""
	nonce := ""
	challenge := ""

	if s.useHydra {
		challenge, err = hydra.ExtractLoginChallenge(r)
		if err != nil {
			return nil, "", err
		}
	} else {
		state, err = extractState(r)
		if err != nil {
			return nil, "", err
		}
		nonce, err = getNonce(r)
		if err != nil {
			return nil, "", err
		}
	}

	stateID, err := s.buildState(idpName, getRealm(r), getClientID(r), scope, redirect, state, nonce, challenge, tx)
	if err != nil {
		return nil, "", err
	}
	return idpConfig(idp, s.getDomainURL(), nil), stateID, nil
}

func idpConfig(idp *pb.IdentityProvider, domainURL string, secrets *pb.IcSecrets) *oauth2.Config {
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

func (s *Service) buildState(idpName, realm, clientID, scope, redirect, state, nonce, challenge string, tx storage.Tx) (string, error) {
	login := &cpb.LoginState{
		IdpName:   idpName,
		Realm:     realm,
		ClientId:  clientID,
		Scope:     scope,
		Redirect:  redirect,
		State:     state,
		Nonce:     nonce,
		Challenge: challenge,
	}

	id := common.GenerateGUID()

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

func buildRedirectNonOIDC(idp *pb.IdentityProvider, idpc *oauth2.Config, state string) string {
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

func (s *Service) login(w http.ResponseWriter, r *http.Request, cfg *pb.IcConfig, idpName, loginHint string) {
	nonce := ""
	redirect := ""
	var err error

	if !s.useHydra {
		nonce, err = getNonce(r)
		if err != nil {
			common.HandleError(http.StatusBadRequest, err, w)
			return
		}
		redirect, err = s.getAndValidateStateRedirect(r, cfg)
		if err != nil {
			common.HandleError(http.StatusBadRequest, err, w)
			return
		}
	}

	idp, ok := cfg.IdentityProviders[idpName]
	if !ok {
		common.HandleError(http.StatusNotFound, fmt.Errorf("login service %q not found", idpName), w)
		return
	}

	idpc, state, err := s.idpAuthorize(idpName, idp, redirect, r, cfg, nil)
	if err != nil {
		common.HandleError(http.StatusBadRequest, err, w)
		return
	}
	resType := idp.ResponseType
	if len(resType) == 0 {
		resType = "code"
	}
	options := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("response_type", resType),
		oauth2.SetAuthURLParam("prompt", "login consent"),
	}
	if len(nonce) > 0 {
		options = append(options, oauth2.SetAuthURLParam("nonce", nonce))
	}
	if len(loginHint) > 0 {
		options = append(options, oauth2.SetAuthURLParam("login_hint", loginHint))
	}

	url := idpc.AuthCodeURL(state, options...)
	url = strings.Replace(url, "${CLIENT_ID}", idp.ClientId, -1)
	url = strings.Replace(url, "${REDIRECT_URI}", buildRedirectNonOIDC(idp, idpc, state), -1)
	common.SendRedirect(url, r, w)
}

// Login login/{name} endpoint handler
func (s *Service) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request method not supported: %q", r.Method), w)
		return
	}
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	s.login(w, r, cfg, getName(r), "")
}

func (s *Service) AcceptLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		common.HandleError(http.StatusUnauthorized, fmt.Errorf("request method not supported: %q", r.Method), w)
		return
	}

	stateParam := common.GetParam(r, "state")
	errStr := common.GetParam(r, "error")
	errDesc := common.GetParam(r, "error_description")
	if len(errStr) > 0 || len(errDesc) > 0 {
		if s.useHydra && len(stateParam) > 0 {
			s.hydraLoginError(w, r, stateParam, errStr, errDesc)
			return
		}
		common.HandleError(http.StatusUnauthorized, fmt.Errorf("authorization error: %q, description: %q", errStr, errDesc), w)
		return
	}

	extract := common.GetParam(r, "client_extract") // makes sure we only grab state from client once

	// Some IdPs need state extracted from html anchor.
	if len(stateParam) == 0 && len(extract) == 0 {
		page := s.clientLoginPage
		page = strings.Replace(page, "${INSTRUCTIONS}", `""`, -1)
		page = pageVariableRE.ReplaceAllString(page, `""`)
		common.SendHTML(page, w)
		return
	}

	var loginState cpb.LoginState
	err := s.store.Read(storage.LoginStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateParam, storage.LatestRev, &loginState)
	if err != nil {
		common.HandleError(http.StatusInternalServerError, fmt.Errorf("read login state failed, %q", err), w)
		return
	}
	if len(loginState.IdpName) == 0 || len(loginState.Realm) == 0 {
		common.HandleError(http.StatusUnauthorized, fmt.Errorf("invalid login state parameter"), w)
		return
	}
	if s.useHydra && len(loginState.Challenge) == 0 {
		common.HandleError(http.StatusUnauthorized, fmt.Errorf("invalid login state parameter"), w)
		return
	}

	// For the purposes of simplifying OIDC redirect_uri registrations, this handler is on a path without
	// realms or other query param context. To make the handling of these requests compatible with the
	// rest of the code, this request will be forwarded to a standard path at "finishLoginPath" and state
	// parameters received from the OIDC call flow will be normalized into query parameters.
	path := strings.Replace(finishLoginPath, "{realm}", loginState.Realm, -1)
	path = strings.Replace(path, "{name}", loginState.IdpName, -1)

	u, err := url.Parse(path)
	if err != nil {
		common.HandleError(http.StatusInternalServerError, fmt.Errorf("bad redirect format: %v", err), w)
		return
	}
	r.Form.Set("client_id", loginState.ClientId)
	u.RawQuery = r.Form.Encode()
	common.SendRedirect(u.String(), r, w)
}

func (s *Service) FinishLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		common.HandleError(http.StatusUnauthorized, fmt.Errorf("request method not supported: %q", r.Method), w)
		return
	}

	code := common.GetParam(r, "code")
	idToken := common.GetParam(r, "id_token")
	accessToken := common.GetParam(r, "access_token")
	stateParam := common.GetParam(r, "state")
	extract := common.GetParam(r, "client_extract") // makes sure we only grab state from client once

	tx, err := s.store.Tx(true)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	defer tx.Finish()

	cfg, err := s.loadConfig(tx, getRealm(r))
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	idpName := getName(r)
	idp, ok := cfg.IdentityProviders[idpName]
	if !ok {
		common.HandleError(http.StatusUnauthorized, fmt.Errorf("invalid identity provider %q", idpName), w)
		return
	}

	if len(extract) == 0 && len(code) == 0 && len(idToken) == 0 && len(accessToken) == 0 {
		instructions := ""
		if len(idp.TokenUrl) > 0 && !strings.HasPrefix(idp.TokenUrl, "http") {
			// Allow the client login page to follow instructions encoded in the TokenUrl.
			// This enables support for some non-OIDC clients.
			instructions = `"` + idp.TokenUrl + `"`
		}
		page := s.clientLoginPage
		page = strings.Replace(page, "${INSTRUCTIONS}", instructions, -1)
		page = pageVariableRE.ReplaceAllString(page, `""`)
		common.SendHTML(page, w)
		return
	}

	var loginState cpb.LoginState
	err = s.store.ReadTx(storage.LoginStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateParam, storage.LatestRev, &loginState, tx)
	if err != nil {
		common.HandleError(http.StatusInternalServerError, fmt.Errorf("read login state failed, %q", err), w)
		return
	}
	// state should be one time usage.
	err = s.store.DeleteTx(storage.LoginStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateParam, storage.LatestRev, tx)
	if err != nil {
		common.HandleError(http.StatusInternalServerError, fmt.Errorf("delete login state failed, %q", err), w)
		return
	}

	// TODO: add security checks here as per OIDC spec.
	if len(loginState.IdpName) == 0 || len(loginState.Realm) == 0 {
		common.HandleError(http.StatusUnauthorized, fmt.Errorf("invalid login state parameter"), w)
		return
	}

	if s.useHydra {
		if len(loginState.Challenge) == 0 {
			common.HandleError(http.StatusUnauthorized, fmt.Errorf("invalid login state parameter"), w)
			return
		}
	} else {
		if len(loginState.ClientId) == 0 || len(loginState.Redirect) == 0 || len(loginState.Nonce) == 0 {
			common.HandleError(http.StatusUnauthorized, fmt.Errorf("invalid login state parameter"), w)
			return
		}
	}

	if len(code) == 0 && len(idToken) == 0 && !s.idpUsesClientLoginPage(loginState.IdpName, loginState.Realm, cfg) {
		common.HandleError(http.StatusUnauthorized, fmt.Errorf("missing auth code"), w)
		return
	}

	redirect := loginState.Redirect
	scope := loginState.Scope
	state := loginState.State
	nonce := loginState.Nonce
	clientID := getClientID(r)
	if !s.useHydra {
		if clientID != loginState.ClientId {
			common.HandleError(http.StatusUnauthorized, fmt.Errorf("request client id does not match login state, want %q, got %q", loginState.ClientId, clientID), w)
			return
		}
	}

	if idpName != loginState.IdpName {
		common.HandleError(http.StatusUnauthorized, fmt.Errorf("request idp does not match login state, want %q, got %q", loginState.IdpName, idpName), w)
		return
	}

	secrets, err := s.loadSecrets(tx)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	if len(accessToken) == 0 {
		idpc := idpConfig(idp, s.getDomainURL(), secrets)
		tok, err := idpc.Exchange(s.ctx, code)
		if err != nil {
			common.HandleError(http.StatusUnauthorized, fmt.Errorf("invalid code: %v", err), w)
			return
		}
		accessToken = tok.AccessToken
		if len(idToken) == 0 {
			idToken, ok = tok.Extra("id_token").(string)
			if !ok && len(accessToken) == 0 {
				common.HandleError(http.StatusUnauthorized, fmt.Errorf("identity provider response does not contain an access_token nor id_token token"), w)
				return
			}
		}
	}

	login, status, err := s.loginTokenToIdentity(accessToken, idToken, idp, r, cfg, secrets)
	if err != nil {
		common.HandleError(status, err, w)
		return
	}

	// If Idp does not support nonce field, use nonce in state instead.
	if len(login.Nonce) == 0 {
		login.Nonce = nonce
	}
	if nonce != login.Nonce {
		common.HandleError(status, fmt.Errorf("nonce in id token is not equal to nonce linked to auth code"), w)
		return
	}

	s.finishLogin(login, idpName, redirect, scope, clientID, state, loginState.Challenge, tx, cfg, secrets, r, w)
}

func (s *Service) Authorize(w http.ResponseWriter, r *http.Request) {
	typ := common.GetParam(r, "response_type")
	if len(typ) == 0 {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("response type required"), w)
		return
	}
	if typ != "code" {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("response type not supported: %q", typ), w)
		return
	}

	// skip login page if request include login_hint.
	loginHint := common.GetParam(r, "login_hint")
	if !strings.Contains(loginHint, ":") {
		s.LoginPage(w, r)
		return
	}

	hint := strings.SplitN(loginHint, ":", 2)
	loginHintProvider := hint[0]
	loginHintAccount := hint[1]

	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}

	// Idp login
	s.login(w, r, cfg, loginHintProvider, loginHintAccount)
}

func getStateRedirect(r *http.Request) (string, error) {
	redirect, err := url.Parse(common.GetParam(r, "redirect_uri"))
	if err != nil {
		return "", fmt.Errorf("redirect_uri missing or invalid: %v", err)
	}
	q := redirect.Query()
	if clientState := common.GetParam(r, "state"); len(clientState) > 0 {
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

func (s *Service) finishLogin(id *ga4gh.Identity, provider, redirect, scope, clientID, state, challenge string, tx storage.Tx, cfg *pb.IcConfig, secrets *pb.IcSecrets, r *http.Request, w http.ResponseWriter) {
	realm := getRealm(r)
	lookup, err := s.accountLookup(realm, id.Subject, tx)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	var subject string
	if isLookupActive(lookup) {
		subject = lookup.Subject
		acct, _, err := s.loadAccount(subject, realm, tx)
		if err != nil {
			common.HandleError(http.StatusServiceUnavailable, err, w)
			return
		}
		claims, err := s.accountLinkToClaims(s.ctx, acct, id.Subject, cfg, secrets)
		if err != nil {
			common.HandleError(http.StatusServiceUnavailable, err, w)
			return
		}
		if !claimsAreEqual(claims, id.GA4GH) {
			// Refresh the claims in the storage layer.
			if err := s.populateAccountClaims(s.ctx, acct, id, provider); err != nil {
				common.HandleError(http.StatusServiceUnavailable, err, w)
				return
			}
			err := s.saveAccount(nil, acct, "REFRESH claims "+id.Subject, r, id.Subject, tx)
			if err != nil {
				common.HandleError(http.StatusServiceUnavailable, err, w)
				return
			}
		}
	} else {
		// Create an account for the identity automatically.
		acct, err := s.newAccountWithLink(s.ctx, id, provider, cfg)
		if err != nil {
			common.HandleError(http.StatusServiceUnavailable, err, w)
			return
		}

		if err = s.saveNewLinkedAccount(acct, id, "New Account", r, tx, lookup); err != nil {
			common.HandleError(http.StatusServiceUnavailable, err, w)
			return
		}
		subject = acct.Properties.Subject
	}

	loginHint := makeLoginHint(provider, id.Subject)

	// redirect to information release page.
	auth := &cpb.AuthTokenState{
		Redirect:  redirect,
		Subject:   subject,
		Scope:     scope,
		Provider:  provider,
		Realm:     realm,
		State:     state,
		Nonce:     id.Nonce,
		LoginHint: loginHint,
	}

	stateID := common.GenerateGUID()

	err = s.store.WriteTx(storage.AuthTokenStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, auth, nil, tx)
	if err != nil {
		common.HandleError(http.StatusInternalServerError, err, w)
		return
	}

	if s.useHydra {
		hydra.SendLoginSuccess(w, r, s.httpClient, s.hydraAdminURL, challenge, subject, stateID)
	} else {
		s.sendInformationReleasePage(id, stateID, extractClientName(cfg, clientID), scope, realm, cfg, w)
	}
}

func (s *Service) sendAuthTokenToRedirect(redirect, subject, scope, provider, realm, state, nonce, loginHint string, cfg *pb.IcConfig, tx storage.Tx, r *http.Request, w http.ResponseWriter) {
	auth, err := s.createAuthToken(subject, scope, provider, realm, nonce, time.Now(), cfg, tx)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	if len(redirect) == 0 {
		common.SendResponse(&cpb.OidcTokenResponse{
			AccessToken: auth,
			TokenType:   "code",
		}, w)
		return
	}
	url, err := url.Parse(redirect)
	if err != nil {
		common.HandleError(http.StatusNotFound, fmt.Errorf("invalid redirect URL format: %v", err), w)
		return
	}
	q := url.Query()
	q.Set("code", auth)
	q.Set("login_hint", loginHint)
	q.Set("state", state)
	url.RawQuery = q.Encode()
	common.SendRedirect(url.String(), r, w)
}

func extractClientName(cfg *pb.IcConfig, clientID string) string {
	clientName := "the application"
	for name, cli := range cfg.Clients {
		if cli.ClientId == clientID {
			if cli.Ui != nil && len(cli.Ui[common.UILabel]) > 0 {
				clientName = cli.Ui[common.UILabel]
			} else {
				clientName = name
			}
			break
		}
	}

	return clientName
}

func (s *Service) sendInformationReleasePage(id *ga4gh.Identity, stateID, clientName, scope, realm string, cfg *pb.IcConfig, w http.ResponseWriter) {
	var info []string
	scopes := strings.Split(scope, " ")

	for _, s := range scopes {
		if s == "openid" && len(id.Subject) != 0 {
			info = append(info, "openid: "+id.Subject)
		}
		if s == "profile" {
			var profile []string
			if len(id.Name) != 0 {
				profile = append(profile, id.Name)
			}
			if len(id.Email) != 0 {
				profile = append(profile, id.Email)
			}
			info = append(info, "profile: "+strings.Join(profile, ","))
		}
		if (s == passportScope || s == ga4ghScope) && len(id.VisaJWTs) != 0 {
			info = append(info, "passport visas")
		}
		if s == "account_admin" {
			info = append(info, "admin claims")
		}
	}

	for i := range info {
		info[i] = "\"" + info[i] + "\""
	}

	page := strings.Replace(s.infomationReleasePage, "${APPLICATION_NAME}", clientName, -1)
	page = strings.Replace(page, "${INFORMATION}", strings.Join(info, ","), -1)
	page = strings.Replace(page, "${STATE}", stateID, -1)
	page = strings.Replace(page, "${PATH}", strings.Replace(acceptInformationReleasePath, "{realm}", realm, -1), -1)

	common.SendHTML(page, w)
}

func (s *Service) acceptInformationRelease(w http.ResponseWriter, r *http.Request) {
	stateID := common.GetParam(r, "state")
	if len(stateID) == 0 {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("missing %q parameter", "state"), w)
		return
	}

	agree := common.GetParam(r, "agree")
	if agree != "y" {
		if s.useHydra {
			s.hydraRejectConsent(w, r, stateID)
			return
		}

		common.HandleError(http.StatusUnauthorized, fmt.Errorf("no information release"), w)
		return
	}

	tx, err := s.store.Tx(true)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	defer tx.Finish()

	state := &cpb.AuthTokenState{}
	err = s.store.ReadTx(storage.AuthTokenStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, state, tx)
	if err != nil {
		common.HandleError(http.StatusInternalServerError, err, w)
		return
	}

	err = s.store.DeleteTx(storage.AuthTokenStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, tx)
	if err != nil {
		common.HandleError(http.StatusInternalServerError, err, w)
		return
	}

	cfg, err := s.loadConfig(tx, state.Realm)
	if err != nil {
		common.HandleError(http.StatusInternalServerError, err, w)
		return
	}

	if s.useHydra {
		s.hydraAcceptConsent(w, r, state, cfg, tx)
	} else {
		s.sendAuthTokenToRedirect(state.Redirect, state.Subject, state.Scope, state.Provider, state.Realm, state.State, state.Nonce, state.LoginHint, cfg, tx, r, w)
	}
}

func (s *Service) Test(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request method not supported: %q", r.Method), w)
		return
	}
	dam := os.Getenv("PERSONA_DAM_URL")
	if len(dam) == 0 {
		scheme := "http:"
		if len(r.URL.Scheme) > 0 {
			scheme = r.URL.Scheme
		}
		dam = strings.Replace(scheme+"//"+s.accountDomain, "ic-", "dam-", -1)
	}

	page := strings.Replace(s.testPage, "${DAM_URL}", dam, -1)
	common.SendHTML(page, w)
}

// TokenFlowTest send token flow test page.
func (s *Service) TokenFlowTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request method not supported: %q", r.Method), w)
		return
	}
	dam := os.Getenv("PERSONA_DAM_URL")
	if len(dam) == 0 {
		scheme := "http:"
		if len(r.URL.Scheme) > 0 {
			scheme = r.URL.Scheme
		}
		dam = strings.Replace(scheme+"//"+s.accountDomain, "ic-", "dam-", -1)
	}

	page := strings.Replace(s.tokenFlowTestPage, "${DAM_URL}", dam, -1)
	common.SendHTML(page, w)
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
			return &realm{
				s:     s,
				w:     w,
				r:     r,
				input: &pb.RealmRequest{},
			}
		},
	}
}

type realm struct {
	s     *Service
	w     http.ResponseWriter
	r     *http.Request
	input *pb.RealmRequest
	item  *pb.Realm
	cfg   *pb.IcConfig
	id    *ga4gh.Identity
}

func (c *realm) Setup(tx storage.Tx, isAdmin bool) (int, error) {
	cfg, _, id, status, err := c.s.handlerSetup(tx, isAdmin, c.r, noScope, c.input)
	c.cfg = cfg
	c.id = id
	return status, err
}
func (c *realm) LookupItem(name string, vars map[string]string) bool {
	// Accept any name that passes the name check.
	c.item = &pb.Realm{}
	return true
}
func (c *realm) NormalizeInput(name string, vars map[string]string) error {
	if err := common.GetRequest(c.input, c.r); err != nil {
		return err
	}
	if c.input == nil {
		c.input = &pb.RealmRequest{}
	}
	if c.input.Item == nil {
		c.input.Item = &pb.Realm{}
	}
	return nil
}
func (c *realm) Get(name string) error {
	if c.item != nil {
		common.SendResponse(c.item, c.w)
	}
	return nil
}
func (c *realm) Post(name string) error {
	// Accept, but do nothing.
	return nil
}
func (c *realm) Put(name string) error {
	// Accept, but do nothing.
	return nil
}
func (c *realm) Patch(name string) error {
	// Accept, but do nothing.
	return nil
}
func (c *realm) Remove(name string) error {
	if err := c.s.store.Wipe(name); err != nil {
		return err
	}
	if name == storage.DefaultRealm {
		return c.s.ImportFiles(importDefault)
	}
	return nil
}
func (c *realm) CheckIntegrity() *status.Status {
	return nil
}
func (c *realm) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	// Accept, but do nothing.
	return nil
}

//////////////////////////////////////////////////////////////////

func (s *Service) clientFactory() *common.HandlerFactory {
	return &common.HandlerFactory{
		TypeName:            "client",
		PathPrefix:          clientPath,
		HasNamedIdentifiers: true,
		IsAdmin:             false,
		NewHandler: func(w http.ResponseWriter, r *http.Request) common.HandlerInterface {
			return &client{
				s:     s,
				w:     w,
				r:     r,
				input: &pb.ClientRequest{},
			}
		},
	}
}

type client struct {
	s     *Service
	w     http.ResponseWriter
	r     *http.Request
	input *pb.ClientRequest
	item  *pb.Client
	cfg   *pb.IcConfig
	id    *ga4gh.Identity
}

func (c *client) Setup(tx storage.Tx, isAdmin bool) (int, error) {
	cfg, _, id, status, err := c.s.handlerSetup(tx, isAdmin, c.r, noScope, c.input)
	c.cfg = cfg
	c.id = id
	return status, err
}
func (c *client) LookupItem(name string, vars map[string]string) bool {
	item, ok := c.cfg.Clients[name]
	if !ok {
		return false
	}
	c.item = item
	return true
}
func (c *client) NormalizeInput(name string, vars map[string]string) error {
	if err := common.GetRequest(c.input, c.r); err != nil {
		return err
	}
	if c.input.Item == nil {
		c.input.Item = &pb.Client{}
	}
	if c.input.Item.Ui == nil {
		c.input.Item.Ui = make(map[string]string)
	}
	return nil
}
func (c *client) Get(name string) error {
	if c.item != nil {
		common.SendResponse(&pb.ClientResponse{
			Client: c.item,
		}, c.w)
	}
	return nil
}
func (c *client) Post(name string) error {
	return fmt.Errorf("POST not allowed")
}
func (c *client) Put(name string) error {
	return fmt.Errorf("PUT not allowed")
}
func (c *client) Patch(name string) error {
	return fmt.Errorf("PATCH not allowed")
}
func (c *client) Remove(name string) error {
	return fmt.Errorf("REMOVE not allowed")
}
func (c *client) CheckIntegrity() *status.Status {
	return nil
}
func (c *client) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	// Accept, but do nothing.
	return nil
}

//////////////////////////////////////////////////////////////////

func (s *Service) configFactory() *common.HandlerFactory {
	return &common.HandlerFactory{
		TypeName:            "config",
		PathPrefix:          configPath,
		HasNamedIdentifiers: false,
		IsAdmin:             true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) common.HandlerInterface {
			return &config{
				s:     s,
				w:     w,
				r:     r,
				input: &pb.ConfigRequest{},
			}
		},
	}
}

type config struct {
	s     *Service
	w     http.ResponseWriter
	r     *http.Request
	input *pb.ConfigRequest
	cfg   *pb.IcConfig
	id    *ga4gh.Identity
}

func (c *config) Setup(tx storage.Tx, isAdmin bool) (int, error) {
	cfg, _, id, status, err := c.s.handlerSetup(tx, isAdmin, c.r, noScope, c.input)
	c.cfg = cfg
	c.id = id
	return status, err
}
func (c *config) LookupItem(name string, vars map[string]string) bool {
	// Trival name as there is only one config.
	return true
}
func (c *config) NormalizeInput(name string, vars map[string]string) error {
	if err := common.GetRequest(c.input, c.r); err != nil {
		return err
	}
	if c.input.Item == nil {
		c.input.Item = &pb.IcConfig{}
	}
	if c.input.Modification == nil {
		c.input.Modification = &pb.ConfigModification{}
	}
	if c.input.Item.IdentityProviders == nil {
		c.input.Item.IdentityProviders = make(map[string]*pb.IdentityProvider)
	}
	if c.input.Item.Clients == nil {
		c.input.Item.Clients = make(map[string]*pb.Client)
	}
	if c.input.Item.Options == nil {
		c.input.Item.Options = &pb.ConfigOptions{}
	}
	c.input.Item.Options = receiveConfigOptions(c.input.Item.Options)
	return nil
}
func (c *config) Get(name string) error {
	common.SendResponse(makeConfig(c.cfg), c.w)
	return nil
}
func (c *config) Post(name string) error {
	return fmt.Errorf("POST not allowed")
}
func (c *config) Put(name string) error {
	if c.cfg.Version != c.input.Item.Version {
		// TODO: consider upgrading older config versions automatically.
		return fmt.Errorf("PUT of config version %q mismatched with existing config version %q", c.input.Item.Version, c.cfg.Version)
	}
	// Retain the revision number (it will be incremented upon saving).
	c.input.Item.Revision = c.cfg.Revision
	return nil
}
func (c *config) Patch(name string) error {
	return fmt.Errorf("PATCH not allowed")
}
func (c *config) Remove(name string) error {
	return fmt.Errorf("DELETE not allowed")
}
func (c *config) CheckIntegrity() *status.Status {
	bad := codes.InvalidArgument
	if err := common.CheckReadOnly(getRealm(c.r), c.cfg.Options.ReadOnlyMasterRealm, c.cfg.Options.WhitelistedRealms); err != nil {
		return common.NewStatus(bad, err.Error())
	}
	if len(c.input.Item.Version) == 0 {
		return common.NewStatus(bad, "missing config version")
	}
	if c.input.Item.Revision <= 0 {
		return common.NewStatus(bad, "invalid config revision")
	}
	if err := configRevision(c.input.Modification, c.cfg); err != nil {
		return common.NewStatus(bad, err.Error())
	}
	if err := c.s.checkConfigIntegrity(c.input.Item); err != nil {
		return common.NewStatus(bad, err.Error())
	}
	return nil
}
func (c *config) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return c.s.saveConfig(c.input.Item, desc, typeName, c.r, c.id, c.cfg, c.input.Item, c.input.Modification, tx)
}

//////////////////////////////////////////////////////////////////

func (s *Service) configIdpFactory() *common.HandlerFactory {
	return &common.HandlerFactory{
		TypeName:            "configIDP",
		PathPrefix:          configIdentityProvidersPath,
		HasNamedIdentifiers: true,
		IsAdmin:             true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) common.HandlerInterface {
			return &configIDP{
				s:     s,
				w:     w,
				r:     r,
				input: &pb.ConfigIdentityProviderRequest{},
			}
		},
	}
}

type configIDP struct {
	s     *Service
	w     http.ResponseWriter
	r     *http.Request
	input *pb.ConfigIdentityProviderRequest
	item  *pb.IdentityProvider
	save  *pb.IdentityProvider
	cfg   *pb.IcConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func (c *configIDP) Setup(tx storage.Tx, isAdmin bool) (int, error) {
	cfg, _, id, status, err := c.s.handlerSetup(tx, isAdmin, c.r, noScope, c.input)
	c.cfg = cfg
	c.id = id
	c.tx = tx
	return status, err
}
func (c *configIDP) LookupItem(name string, vars map[string]string) bool {
	if item, ok := c.cfg.IdentityProviders[name]; ok {
		c.item = item
		return true
	}
	return false
}
func (c *configIDP) NormalizeInput(name string, vars map[string]string) error {
	if err := common.GetRequest(c.input, c.r); err != nil {
		return err
	}
	if c.input.Item == nil {
		c.input.Item = &pb.IdentityProvider{}
	}
	if c.input.Item.Scopes == nil {
		c.input.Item.Scopes = []string{}
	}
	if c.input.Item.Ui == nil {
		c.input.Item.Ui = make(map[string]string)
	}
	return nil
}
func (c *configIDP) Get(name string) error {
	common.SendResponse(c.item, c.w)
	return nil
}
func (c *configIDP) Post(name string) error {
	c.save = c.input.Item
	c.cfg.IdentityProviders[name] = c.save
	return nil
}
func (c *configIDP) Put(name string) error {
	c.save = c.input.Item
	c.cfg.IdentityProviders[name] = c.save
	return nil
}
func (c *configIDP) Patch(name string) error {
	c.save = &pb.IdentityProvider{}
	proto.Merge(c.save, c.item)
	proto.Merge(c.save, c.input.Item)
	c.save.Scopes = c.input.Item.Scopes
	c.save.Ui = c.input.Item.Ui
	c.cfg.IdentityProviders[name] = c.save
	return nil
}
func (c *configIDP) Remove(name string) error {
	delete(c.cfg.IdentityProviders, name)
	c.save = &pb.IdentityProvider{}
	return nil
}
func (c *configIDP) CheckIntegrity() *status.Status {
	bad := codes.InvalidArgument
	if err := common.CheckReadOnly(getRealm(c.r), c.cfg.Options.ReadOnlyMasterRealm, c.cfg.Options.WhitelistedRealms); err != nil {
		return common.NewStatus(bad, err.Error())
	}
	if err := configRevision(c.input.Modification, c.cfg); err != nil {
		return common.NewStatus(bad, err.Error())
	}
	if err := c.s.checkConfigIntegrity(c.cfg); err != nil {
		return common.NewStatus(bad, err.Error())
	}
	return nil
}
func (c *configIDP) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	if c.save == nil || (c.input.Modification != nil && c.input.Modification.DryRun) {
		return nil
	}
	if err := c.s.saveConfig(c.cfg, desc, typeName, c.r, c.id, c.item, c.save, c.input.Modification, c.tx); err != nil {
		return err
	}
	return nil
}

//////////////////////////////////////////////////////////////////

func (s *Service) configClientFactory() *common.HandlerFactory {
	return &common.HandlerFactory{
		TypeName:            "configClient",
		PathPrefix:          configClientsPath,
		HasNamedIdentifiers: true,
		IsAdmin:             true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) common.HandlerInterface {
			return &configClient{
				s:     s,
				w:     w,
				r:     r,
				input: &pb.ConfigClientRequest{},
			}
		},
	}
}

type configClient struct {
	s     *Service
	w     http.ResponseWriter
	r     *http.Request
	input *pb.ConfigClientRequest
	item  *pb.Client
	save  *pb.Client
	cfg   *pb.IcConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func (c *configClient) Setup(tx storage.Tx, isAdmin bool) (int, error) {
	cfg, _, id, status, err := c.s.handlerSetup(tx, isAdmin, c.r, noScope, c.input)
	c.cfg = cfg
	c.id = id
	c.tx = tx
	return status, err
}
func (c *configClient) LookupItem(name string, vars map[string]string) bool {
	if item, ok := c.cfg.Clients[name]; ok {
		c.item = item
		return true
	}
	return false
}
func (c *configClient) NormalizeInput(name string, vars map[string]string) error {
	if err := common.GetRequest(c.input, c.r); err != nil {
		return err
	}
	if c.input.Item == nil {
		c.input.Item = &pb.Client{}
	}
	if c.input.Item.RedirectUris == nil {
		c.input.Item.RedirectUris = []string{}
	}
	if c.input.Item.Ui == nil {
		c.input.Item.Ui = make(map[string]string)
	}
	return nil
}
func (c *configClient) Get(name string) error {
	common.SendResponse(c.item, c.w)
	return nil
}
func (c *configClient) Post(name string) error {
	c.save = c.input.Item
	c.cfg.Clients[name] = c.save
	return nil
}
func (c *configClient) Put(name string) error {
	c.save = c.input.Item
	c.cfg.Clients[name] = c.save
	return nil
}
func (c *configClient) Patch(name string) error {
	c.save = &pb.Client{}
	proto.Merge(c.save, c.item)
	proto.Merge(c.save, c.input.Item)
	c.save.RedirectUris = c.input.Item.RedirectUris
	c.save.Ui = c.input.Item.Ui
	c.cfg.Clients[name] = c.save
	return nil
}
func (c *configClient) Remove(name string) error {
	delete(c.cfg.Clients, name)
	c.save = &pb.Client{}
	return nil
}
func (c *configClient) CheckIntegrity() *status.Status {
	bad := codes.InvalidArgument
	if err := common.CheckReadOnly(getRealm(c.r), c.cfg.Options.ReadOnlyMasterRealm, c.cfg.Options.WhitelistedRealms); err != nil {
		return common.NewStatus(bad, err.Error())
	}
	if err := configRevision(c.input.Modification, c.cfg); err != nil {
		return common.NewStatus(bad, err.Error())
	}
	if err := c.s.checkConfigIntegrity(c.cfg); err != nil {
		return common.NewStatus(bad, err.Error())
	}
	return nil
}
func (c *configClient) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	if c.save == nil || (c.input.Modification != nil && c.input.Modification.DryRun) {
		return nil
	}
	if err := c.s.saveConfig(c.cfg, desc, typeName, c.r, c.id, c.item, c.save, c.input.Modification, c.tx); err != nil {
		return err
	}
	return nil
}

//////////////////////////////////////////////////////////////////

func (s *Service) configOptionsFactory() *common.HandlerFactory {
	return &common.HandlerFactory{
		TypeName:            "configOptions",
		PathPrefix:          configOptionsPath,
		HasNamedIdentifiers: false,
		IsAdmin:             true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) common.HandlerInterface {
			return &configOptions{
				s:     s,
				w:     w,
				r:     r,
				input: &pb.ConfigOptionsRequest{},
			}
		},
	}
}

type configOptions struct {
	s     *Service
	w     http.ResponseWriter
	r     *http.Request
	input *pb.ConfigOptionsRequest
	item  *pb.ConfigOptions
	save  *pb.ConfigOptions
	cfg   *pb.IcConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func (c *configOptions) Setup(tx storage.Tx, isAdmin bool) (int, error) {
	cfg, _, id, status, err := c.s.handlerSetup(tx, isAdmin, c.r, noScope, c.input)
	c.cfg = cfg
	c.id = id
	c.tx = tx
	return status, err
}
func (c *configOptions) LookupItem(name string, vars map[string]string) bool {
	c.item = c.cfg.Options
	return true
}
func (c *configOptions) NormalizeInput(name string, vars map[string]string) error {
	if err := common.GetRequest(c.input, c.r); err != nil {
		return err
	}
	if c.input.Item == nil {
		c.input.Item = &pb.ConfigOptions{}
	}
	c.input.Item = receiveConfigOptions(c.input.Item)
	return nil
}
func (c *configOptions) Get(name string) error {
	common.SendResponse(makeConfigOptions(c.item), c.w)
	return nil
}
func (c *configOptions) Post(name string) error {
	c.save = c.input.Item
	c.cfg.Options = c.save
	return nil
}
func (c *configOptions) Put(name string) error {
	c.save = c.input.Item
	c.cfg.Options = c.save
	return nil
}
func (c *configOptions) Patch(name string) error {
	c.save = &pb.ConfigOptions{}
	proto.Merge(c.save, c.item)
	proto.Merge(c.save, c.input.Item)
	c.save.ReadOnlyMasterRealm = c.input.Item.ReadOnlyMasterRealm
	c.cfg.Options = c.save
	return nil
}
func (c *configOptions) Remove(name string) error {
	return fmt.Errorf("DELETE not allowed")
}
func (c *configOptions) CheckIntegrity() *status.Status {
	bad := codes.InvalidArgument
	if err := common.CheckReadOnly(getRealm(c.r), c.cfg.Options.ReadOnlyMasterRealm, c.cfg.Options.WhitelistedRealms); err != nil {
		return common.NewStatus(bad, err.Error())
	}
	if err := configRevision(c.input.Modification, c.cfg); err != nil {
		return common.NewStatus(bad, err.Error())
	}
	if err := c.s.checkConfigIntegrity(c.cfg); err != nil {
		return common.NewStatus(bad, err.Error())
	}
	return nil
}
func (c *configOptions) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	if c.save == nil || (c.input.Modification != nil && c.input.Modification.DryRun) {
		return nil
	}
	if err := c.s.saveConfig(c.cfg, desc, typeName, c.r, c.id, c.item, c.save, c.input.Modification, c.tx); err != nil {
		return err
	}
	return nil
}

//////////////////////////////////////////////////////////////////

func (s *Service) tokenMetadataFactory() *common.HandlerFactory {
	return &common.HandlerFactory{
		TypeName:            "token",
		PathPrefix:          tokenMetadataPath,
		HasNamedIdentifiers: true,
		IsAdmin:             false,
		NameChecker: map[string]*regexp.Regexp{
			"sub": common.SubRE,
			"jti": common.JTIRE,
		},
		NewHandler: func(w http.ResponseWriter, r *http.Request) common.HandlerInterface {
			return &tokenMetadataHandler{
				s:     s,
				w:     w,
				r:     r,
				input: &pb.TokenMetadataRequest{},
			}
		},
	}
}

type tokenMetadataHandler struct {
	s     *Service
	w     http.ResponseWriter
	r     *http.Request
	input *pb.TokenMetadataRequest
	sub   string
	jti   string
	item  *pb.TokenMetadata
	id    *ga4gh.Identity
	tx    storage.Tx
}

func (h *tokenMetadataHandler) Setup(tx storage.Tx, isAdmin bool) (int, error) {
	_, _, id, status, err := h.s.handlerSetup(tx, isAdmin, h.r, noScope, h.input)
	h.id = id
	h.tx = tx
	return status, err
}

func (h *tokenMetadataHandler) LookupItem(name string, vars map[string]string) bool {
	sub, ok := vars["sub"]
	if !ok {
		return false
	}
	h.sub = sub
	if _, err := h.s.permissions.CheckSubjectOrAdmin(h.id, sub); err != nil {
		return false
	}

	jti, ok := vars["jti"]
	if !ok || len(jti) == 0 {
		return false
	}
	h.jti = jti

	h.item = &pb.TokenMetadata{}
	if err := h.s.store.ReadTx(storage.TokensDatatype, getRealm(h.r), sub, jti, storage.LatestRev, h.item, h.tx); err != nil {
		return false
	}
	return true
}

func (h *tokenMetadataHandler) NormalizeInput(name string, vars map[string]string) error {
	return common.GetRequest(h.input, h.r)
}

func (h *tokenMetadataHandler) Get(name string) error {
	common.SendResponse(&pb.TokenMetadataResponse{
		TokenMetadata: h.item,
	}, h.w)
	return nil
}

func (h *tokenMetadataHandler) Post(name string) error {
	return fmt.Errorf("POST not allowed")
}

func (h *tokenMetadataHandler) Put(name string) error {
	return fmt.Errorf("PUT not allowed")
}

func (h *tokenMetadataHandler) Patch(name string) error {
	return fmt.Errorf("PATCH not allowed")
}

func (h *tokenMetadataHandler) Remove(name string) error {
	return h.s.store.DeleteTx(storage.TokensDatatype, getRealm(h.r), h.sub, h.jti, storage.LatestRev, h.tx)
}

func (h *tokenMetadataHandler) CheckIntegrity() *status.Status {
	return nil
}

func (h *tokenMetadataHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return nil
}

//////////////////////////////////////////////////////////////////

func (s *Service) adminTokenMetadataFactory() *common.HandlerFactory {
	return &common.HandlerFactory{
		TypeName:            "tokens",
		PathPrefix:          adminTokenMetadataPath,
		HasNamedIdentifiers: false,
		IsAdmin:             true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) common.HandlerInterface {
			return &adminTokenMetadataHandler{
				s:     s,
				w:     w,
				r:     r,
				input: &pb.TokensMetadataRequest{},
			}
		},
	}
}

type adminTokenMetadataHandler struct {
	s     *Service
	w     http.ResponseWriter
	r     *http.Request
	input *pb.TokensMetadataRequest
	item  map[string]*pb.TokenMetadata
	tx    storage.Tx
}

func (h *adminTokenMetadataHandler) Setup(tx storage.Tx, isAdmin bool) (int, error) {
	h.tx = tx
	_, _, _, status, err := h.s.handlerSetup(tx, isAdmin, h.r, noScope, h.input)
	return status, err
}

func (h *adminTokenMetadataHandler) LookupItem(name string, vars map[string]string) bool {
	h.item = make(map[string]*pb.TokenMetadata)
	m := make(map[string]map[string]proto.Message)
	err := h.s.store.MultiReadTx(storage.TokensDatatype, getRealm(h.r), storage.DefaultUser, m, &pb.TokenMetadata{}, h.tx)
	if err != nil {
		return false
	}
	for userKey, userVal := range m {
		for idKey, idVal := range userVal {
			if id, ok := idVal.(*pb.TokenMetadata); ok {
				h.item[userKey+"/"+idKey] = id
			}
		}
	}
	return true
}

func (h *adminTokenMetadataHandler) NormalizeInput(name string, vars map[string]string) error {
	return common.GetRequest(h.input, h.r)
}

func (h *adminTokenMetadataHandler) Get(name string) error {
	item := h.item
	if len(item) == 0 {
		item = nil
	}
	common.SendResponse(&pb.TokensMetadataResponse{
		TokensMetadata: item,
	}, h.w)
	return nil
}

func (h *adminTokenMetadataHandler) Post(name string) error {
	return fmt.Errorf("POST not allowed")
}

func (h *adminTokenMetadataHandler) Put(name string) error {
	return fmt.Errorf("PUT not allowed")
}

func (h *adminTokenMetadataHandler) Patch(name string) error {
	return fmt.Errorf("PATCH not allowed")
}

func (h *adminTokenMetadataHandler) Remove(name string) error {
	return h.s.store.MultiDeleteTx(storage.TokensDatatype, getRealm(h.r), storage.DefaultUser, h.tx)
}

func (h *adminTokenMetadataHandler) CheckIntegrity() *status.Status {
	return nil
}

func (h *adminTokenMetadataHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return nil
}

//////////////////////////////////////////////////////////////////

func (s *Service) accountFactory() *common.HandlerFactory {
	return &common.HandlerFactory{
		TypeName:            "account",
		PathPrefix:          accountPath,
		HasNamedIdentifiers: true,
		IsAdmin:             false,
		NameChecker: map[string]*regexp.Regexp{
			"name": common.PlaceholderOrNameRE,
		},
		NewHandler: func(w http.ResponseWriter, r *http.Request) common.HandlerInterface {
			return &account{
				s:     s,
				w:     w,
				r:     r,
				input: &pb.AccountRequest{},
			}
		},
	}
}

type account struct {
	s     *Service
	w     http.ResponseWriter
	r     *http.Request
	item  *pb.Account
	input *pb.AccountRequest
	save  *pb.Account
	cfg   *pb.IcConfig
	sec   *pb.IcSecrets
	id    *ga4gh.Identity
	tx    storage.Tx
}

func (c *account) Setup(tx storage.Tx, isAdmin bool) (int, error) {
	cfg, sec, id, status, err := c.s.handlerSetup(tx, isAdmin, c.r, noScope, c.input)
	c.cfg = cfg
	c.sec = sec
	c.id = id
	c.tx = tx
	return status, err
}
func (c *account) LookupItem(name string, vars map[string]string) bool {
	if name == common.PlaceholderName {
		name = c.id.Subject
	} else if strings.Contains(name, "@") {
		lookup, err := c.s.accountLookup(getRealm(c.r), name, c.tx)
		if err != nil || !isLookupActive(lookup) {
			return false
		}
		name = lookup.Subject
	}
	if _, err := c.s.permissions.CheckSubjectOrAdmin(c.id, name); err != nil {
		return false
	}
	acct, _, err := c.s.loadAccount(name, getRealm(c.r), c.tx)
	if err != nil {
		return false
	}
	c.item = acct
	return true
}
func (c *account) NormalizeInput(name string, vars map[string]string) error {
	if err := common.GetRequest(c.input, c.r); err != nil {
		return err
	}
	if c.input.Item == nil {
		c.input.Item = &pb.Account{}
	}
	if c.input.Modification == nil {
		c.input.Modification = &pb.ConfigModification{}
	}
	if c.input.Item.Profile == nil {
		c.input.Item.Profile = &pb.AccountProfile{}
	}
	if c.input.Item.Ui == nil {
		c.input.Item.Ui = make(map[string]string)
	}
	if c.input.Item.ConnectedAccounts == nil {
		c.input.Item.ConnectedAccounts = []*pb.ConnectedAccount{}
	}
	for _, a := range c.input.Item.ConnectedAccounts {
		if a.Profile == nil {
			a.Profile = &pb.AccountProfile{}
		}
		if a.Properties == nil {
			a.Properties = &pb.AccountProperties{}
		}
		if a.Passport == nil {
			a.Passport = &cpb.Passport{}
		}
		a.ComputedIdentityProvider = nil
	}
	return nil
}
func (c *account) Get(name string) error {
	secrets, err := c.s.loadSecrets(c.tx)
	if err != nil {
		// Do not expose internal errors related to secrets to users, return generic error instead.
		return fmt.Errorf("internal system information unavailable")
	}
	common.SendResponse(&pb.AccountResponse{
		Account: c.s.makeAccount(c.s.ctx, c.item, c.cfg, secrets),
	}, c.w)
	return nil
}
func (c *account) Post(name string) error {
	return fmt.Errorf("POST not allowed")
}
func (c *account) Put(name string) error {
	return fmt.Errorf("PUT not allowed")
}
func (c *account) Patch(name string) error {
	c.save = &pb.Account{}
	proto.Merge(c.save, c.item)
	link := common.GetParam(c.r, "link_token")
	if len(link) > 0 {
		if !hasScopes("link", c.id.Scope, matchFullScope) {
			return fmt.Errorf("bearer token unauthorized for scope %q", "link")
		}
		linkID, _, err := c.s.tokenToIdentity(link, c.r, "link:"+c.item.Properties.Subject, getRealm(c.r), c.cfg, c.sec, c.tx)
		if err != nil {
			return err
		}
		linkSub := linkID.Subject
		idSub := c.item.Properties.Subject
		if linkSub == idSub {
			return fmt.Errorf("the accounts provided are already linked together")
		}
		linkAcct, _, err := c.s.loadAccount(linkSub, getRealm(c.r), c.tx)
		if err != nil {
			return err
		}
		if linkAcct.State != "ACTIVE" {
			return fmt.Errorf("the link account is not found or no longer available")
		}
		for _, acct := range linkAcct.ConnectedAccounts {
			if acct.Properties == nil || len(acct.Properties.Subject) == 0 {
				continue
			}
			if c.input.Modification != nil && c.input.Modification.DryRun {
				continue
			}
			lookup := &pb.AccountLookup{
				Subject:  c.item.Properties.Subject,
				Revision: acct.LinkRevision,
				State:    "ACTIVE",
			}
			if err := c.s.saveAccountLookup(lookup, getRealm(c.r), acct.Properties.Subject, c.r, c.id, c.tx); err != nil {
				return fmt.Errorf("service dependencies not available; try again later")
			}
			acct.LinkRevision++
			c.save.ConnectedAccounts = append(c.save.ConnectedAccounts, acct)
		}
		linkAcct.ConnectedAccounts = make([]*pb.ConnectedAccount, 0)
		linkAcct.State = "LINKED"
		linkAcct.Owner = c.item.Properties.Subject
		if c.input.Modification == nil || !c.input.Modification.DryRun {
			err := c.s.saveAccount(nil, linkAcct, "LINK account", c.r, c.id.Subject, c.tx)
			if err != nil {
				return err
			}
		}
	} else {
		// PATCH Profile, but not core elements like subject and timestamps.
		if len(c.input.Item.Ui) > 0 {
			c.save.Ui = c.input.Item.Ui
		}
		proto.Merge(c.save.Profile, c.input.Item.Profile)
	}
	return nil
}
func (c *account) Remove(name string) error {
	if c.input.Modification != nil && c.input.Modification.DryRun {
		return nil
	}
	c.save = &pb.Account{}
	proto.Merge(c.save, c.item)
	for _, link := range c.save.ConnectedAccounts {
		if link.Properties == nil || len(link.Properties.Subject) == 0 {
			continue
		}
		if err := c.s.removeAccountLookup(link.LinkRevision, getRealm(c.r), link.Properties.Subject, c.r, c.id, c.tx); err != nil {
			return fmt.Errorf("service dependencies not available; try again later")
		}
	}
	c.save.ConnectedAccounts = []*pb.ConnectedAccount{}
	c.save.State = "DELETED"
	return nil
}
func (c *account) CheckIntegrity() *status.Status {
	// TODO: add more checks for accounts here.
	return nil
}
func (c *account) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	if c.save == nil || (c.input.Modification != nil && c.input.Modification.DryRun) {
		return nil
	}
	if err := c.s.saveAccount(c.item, c.save, desc, c.r, c.id.Subject, c.tx); err != nil {
		return err
	}
	return nil
}

//////////////////////////////////////////////////////////////////

func (s *Service) accountSubjectFactory() *common.HandlerFactory {
	return &common.HandlerFactory{
		TypeName:            "accountLink",
		PathPrefix:          accountSubjectPath,
		HasNamedIdentifiers: true,
		IsAdmin:             false,
		NameChecker: map[string]*regexp.Regexp{
			// Some upstream IdPs may use a wider selection of characters, including email-looking format.
			"subject": regexp.MustCompile(`^[\w][^/\\@]*@?[\w][^/\\@]*$`),
		},
		NewHandler: func(w http.ResponseWriter, r *http.Request) common.HandlerInterface {
			return &accountLink{
				s:     s,
				w:     w,
				r:     r,
				input: &pb.AccountSubjectRequest{},
			}
		},
	}
}

type accountLink struct {
	s         *Service
	w         http.ResponseWriter
	r         *http.Request
	acct      *pb.Account
	item      *pb.ConnectedAccount
	itemIndex int
	input     *pb.AccountSubjectRequest
	save      *pb.Account
	cfg       *pb.IcConfig
	id        *ga4gh.Identity
	tx        storage.Tx
}

func (c *accountLink) Setup(tx storage.Tx, isAdmin bool) (int, error) {
	cfg, _, id, status, err := c.s.handlerSetup(tx, isAdmin, c.r, noScope, c.input)
	c.cfg = cfg
	c.id = id
	c.tx = tx
	return status, err
}
func (c *accountLink) LookupItem(name string, vars map[string]string) bool {
	acct, _, err := c.s.loadAccount(name, getRealm(c.r), c.tx)
	if err != nil {
		return false
	}
	c.acct = acct
	if link, i := findLinkedAccount(acct, vars["subject"]); link != nil {
		c.item = link
		c.itemIndex = i
		return true
	}
	return false
}
func (c *accountLink) NormalizeInput(name string, vars map[string]string) error {
	if err := common.GetRequest(c.input, c.r); err != nil {
		return err
	}
	if c.input.Item == nil {
		c.input.Item = &pb.ConnectedAccount{}
	}
	if c.input.Item.Profile == nil {
		c.input.Item.Profile = &pb.AccountProfile{}
	}
	if c.input.Item.Passport == nil {
		c.input.Item.Passport = &cpb.Passport{}
	}
	c.input.Item.ComputedIdentityProvider = nil
	return nil
}
func (c *accountLink) Get(name string) error {
	secrets, err := c.s.loadSecrets(c.tx)
	if err != nil {
		// Do not expose internal errors related to secrets to users, return generic error instead.
		return fmt.Errorf("internal system information unavailable")
	}
	common.SendResponse(&pb.AccountSubjectResponse{
		Item: c.s.makeConnectedAccount(c.s.ctx, c.item, c.cfg, secrets),
	}, c.w)
	return nil
}
func (c *accountLink) Post(name string) error {
	return fmt.Errorf("POST not allowed")
}
func (c *accountLink) Put(name string) error {
	return fmt.Errorf("PUT not allowed")
}
func (c *accountLink) Patch(name string) error {
	return fmt.Errorf("PATCH not allowed")
}
func (c *accountLink) Remove(name string) error {
	if c.input.Modification != nil && c.input.Modification.DryRun {
		return nil
	}
	c.save = &pb.Account{}
	proto.Merge(c.save, c.acct)
	c.save.ConnectedAccounts = append(c.save.ConnectedAccounts[:c.itemIndex], c.save.ConnectedAccounts[c.itemIndex+1:]...)
	if len(c.save.ConnectedAccounts) == 0 {
		return fmt.Errorf("cannot remove primary linked account; delete full account instead")
	}
	if err := c.s.removeAccountLookup(c.item.LinkRevision, getRealm(c.r), c.item.Properties.Subject, c.r, c.id, c.tx); err != nil {
		return fmt.Errorf("service dependencies not available; try again later")
	}
	return nil
}
func (c *accountLink) CheckIntegrity() *status.Status {
	// TODO: add more checks for accounts here (such as removing the primary email account).
	return nil
}
func (c *accountLink) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	if c.save == nil || (c.input.Modification != nil && c.input.Modification.DryRun) {
		return nil
	}
	if err := c.s.saveAccount(c.acct, c.save, desc, c.r, c.id.Subject, c.tx); err != nil {
		return err
	}
	return nil
}

//////////////////////////////////////////////////////////////////

func (s *Service) adminClaimsFactory() *common.HandlerFactory {
	return &common.HandlerFactory{
		TypeName:            "adminClaims",
		PathPrefix:          adminClaimsPath,
		HasNamedIdentifiers: false,
		IsAdmin:             true,
		NameChecker: map[string]*regexp.Regexp{
			"name": regexp.MustCompile(`^[\w][^/\\]*@[\w][^/\\]*$`),
		},
		NewHandler: func(w http.ResponseWriter, r *http.Request) common.HandlerInterface {
			return &adminClaims{
				s:     s,
				w:     w,
				r:     r,
				input: &pb.SubjectClaimsRequest{},
			}
		},
	}
}

type adminClaims struct {
	s     *Service
	w     http.ResponseWriter
	r     *http.Request
	item  *pb.Account
	input *pb.SubjectClaimsRequest
	save  *pb.Account
	cfg   *pb.IcConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func (c *adminClaims) Setup(tx storage.Tx, isAdmin bool) (int, error) {
	cfg, _, id, status, err := c.s.handlerSetup(tx, isAdmin, c.r, noScope, c.input)
	c.cfg = cfg
	c.id = id
	c.tx = tx
	return status, err
}
func (c *adminClaims) LookupItem(name string, vars map[string]string) bool {
	acct, _, err := c.s.lookupAccount(name, getRealm(c.r), c.tx)
	if err != nil {
		return false
	}
	c.item = acct
	return true
}
func (c *adminClaims) NormalizeInput(name string, vars map[string]string) error {
	if err := common.GetRequest(c.input, c.r); err != nil {
		return err
	}
	return nil
}
func (c *adminClaims) Get(name string) error {
	// Collect all claims across linked accounts.
	out := []*cpb.Assertion{}
	for _, link := range c.item.ConnectedAccounts {
		if link.Passport == nil {
			continue
		}
		for _, v := range link.Passport.Ga4GhAssertions {
			out = append(out, v)
		}
	}

	common.SendResponse(&pb.SubjectClaimsResponse{
		Assertions: out,
	}, c.w)
	return nil
}
func (c *adminClaims) Post(name string) error {
	return fmt.Errorf("POST not allowed")
}
func (c *adminClaims) Put(name string) error {
	return fmt.Errorf("PUT not allowed")
}
func (c *adminClaims) Patch(name string) error {
	return fmt.Errorf("PATCH not allowed")
}
func (c *adminClaims) Remove(name string) error {
	if c.input.Modification != nil && c.input.Modification.DryRun {
		return nil
	}
	c.save = &pb.Account{}
	proto.Merge(c.save, c.item)
	for _, link := range c.save.ConnectedAccounts {
		link.Passport = &cpb.Passport{}
	}
	return nil
}
func (c *adminClaims) CheckIntegrity() *status.Status {
	return nil
}
func (c *adminClaims) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	if c.save == nil || (c.input.Modification != nil && c.input.Modification.DryRun) {
		return nil
	}
	if err := c.s.saveAccount(c.item, c.save, desc, c.r, c.id.Subject, c.tx); err != nil {
		return err
	}
	return nil
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

func (s *Service) handlerSetup(tx storage.Tx, isAdmin bool, r *http.Request, scope string, item proto.Message) (*pb.IcConfig, *pb.IcSecrets, *ga4gh.Identity, int, error) {
	if item != nil {
		if err := jsonpb.Unmarshal(r.Body, item); err != nil && err != io.EOF {
			return nil, nil, nil, http.StatusBadRequest, err
		}
	}
	cfg, err := s.loadConfig(tx, getRealm(r))
	if err != nil {
		return nil, nil, nil, http.StatusServiceUnavailable, err
	}
	secrets, err := s.loadSecrets(tx)
	if err != nil {
		return nil, nil, nil, http.StatusServiceUnavailable, err
	}
	id, status, err := s.getIdentity(r, scope, getRealm(r), cfg, secrets, tx)
	if err != nil {
		return nil, nil, nil, status, err
	}
	// TODO: use only isAdmin by upgrading each handler to set this flag.
	path := common.RequestAbstractPath(r)
	if strings.HasPrefix(path, configPathPrefix) || isAdmin {
		if status, err := s.permissions.CheckAdmin(id); err != nil {
			return nil, nil, nil, status, err
		}
	}
	if path == realmPath {
		if status, err := s.permissions.CheckAdmin(id); err != nil {
			return nil, nil, nil, status, err
		}
	}
	return cfg, secrets, id, status, err
}

func (s *Service) getIdentity(r *http.Request, scope, realm string, cfg *pb.IcConfig, secrets *pb.IcSecrets, tx storage.Tx) (*ga4gh.Identity, int, error) {
	tok, status, err := getAuthCode(r)
	if err != nil {
		return nil, status, err
	}
	return s.tokenToIdentity(tok, r, scope, realm, cfg, secrets, tx)
}

func (s *Service) tokenRealm(r *http.Request) (string, int, error) {
	tok, status, err := getAuthCode(r)
	if err != nil {
		return "", status, err
	}
	id, err := common.ConvertTokenToIdentityUnsafe(tok)
	if err != nil {
		return "", http.StatusUnauthorized, fmt.Errorf("inspecting token: %v", err)
	}
	realm := id.Realm
	if len(realm) == 0 {
		return storage.DefaultRealm, http.StatusOK, nil
	}
	return realm, http.StatusOK, nil
}

func defaultPermissionTTL(cfg *pb.IcConfig) time.Duration {
	return getDurationOption(cfg.Options.MaxPassportTokenTtl, descMaxPassportTokenTTL)
}

func getAuthCode(r *http.Request) (string, int, error) {
	tok := common.GetParam(r, "code")
	if tok == "" {
		tok = getBearerToken(r)
		if len(tok) == 0 {
			return "", http.StatusUnauthorized, fmt.Errorf("authorization requires a bearer token")
		}
	}
	return tok, http.StatusOK, nil
}

func (s *Service) authCodeToIdentity(code string, r *http.Request, cfg *pb.IcConfig, secrets *pb.IcSecrets, tx storage.Tx) (*ga4gh.Identity, int, error) {
	id, err := common.ConvertTokenToIdentityUnsafe(code)
	if err != nil {
		return nil, http.StatusUnauthorized, fmt.Errorf("inspecting token: %v", err)
	}
	if err := id.Valid(); err != nil {
		return nil, http.StatusUnauthorized, err
	}
	realm := getRealm(r)
	var tokenMetadata pb.TokenMetadata
	if err := s.store.ReadTx(storage.AuthCodeDatatype, realm, storage.DefaultUser, id.ID, storage.LatestRev, &tokenMetadata, tx); err != nil {
		if storage.ErrNotFound(err) {
			return nil, http.StatusUnauthorized, fmt.Errorf("auth code invalid or has already been exchanged")
		}
		return nil, http.StatusServiceUnavailable, fmt.Errorf("reading auth code metadata from storage: %v", err)
	}
	if err := s.store.DeleteTx(storage.AuthCodeDatatype, realm, storage.DefaultUser, id.ID, storage.LatestRev, tx); err != nil {
		return nil, http.StatusServiceUnavailable, fmt.Errorf("removing auth code metadata from storage: %v", err)
	}

	id.Subject = tokenMetadata.Subject
	id.Scope = tokenMetadata.Scope
	id.IdentityProvider = tokenMetadata.IdentityProvider
	id.Nonce = tokenMetadata.Nonce
	return s.getTokenAccountIdentity(s.ctx, id, realm, cfg, secrets, tx)
}

func (s *Service) getTokenIdentity(tok, scope, clientID string, anyAudience bool, tx storage.Tx) (*ga4gh.Identity, int, error) {
	id, err := common.ConvertTokenToIdentityUnsafe(tok)
	if err != nil {
		return nil, http.StatusUnauthorized, fmt.Errorf("inspecting token: %v", err)
	}

	// TODO: add more checks here as appropriate.
	iss := s.getIssuerString()
	if err = id.Valid(); err != nil {
		return nil, http.StatusUnauthorized, err
	} else if id.Issuer != iss {
		return nil, http.StatusUnauthorized, fmt.Errorf("bearer token unauthorized for issuer %q", id.Issuer)
	} else if len(scope) > 0 && !hasScopes(scope, id.Scope, matchFullScope) {
		return nil, http.StatusUnauthorized, fmt.Errorf("bearer token unauthorized for scope %q", scope)
	} else if !anyAudience && !common.IsAudience(id, clientID, iss) {
		return nil, http.StatusUnauthorized, fmt.Errorf("bearer token unauthorized party")
	}
	return id, http.StatusOK, nil
}

func (s *Service) getTokenAccountIdentity(ctx context.Context, token *ga4gh.Identity, realm string, cfg *pb.IcConfig, secrets *pb.IcSecrets, tx storage.Tx) (*ga4gh.Identity, int, error) {
	acct, status, err := s.loadAccount(token.Subject, realm, tx)
	if err != nil {
		if status == http.StatusNotFound {
			return nil, http.StatusUnauthorized, fmt.Errorf("bearer token unauthorized account")
		}
		return nil, http.StatusServiceUnavailable, err
	}
	id, err := s.accountToIdentity(ctx, acct, cfg, secrets)
	if err != nil {
		return nil, http.StatusServiceUnavailable, err
	}

	id.ID = token.ID
	id.Scope = token.Scope
	id.Expiry = token.Expiry
	id.IdentityProvider = token.IdentityProvider
	id.Nonce = token.Nonce
	return id, http.StatusOK, nil
}

func (s *Service) tokenToIdentity(tok string, r *http.Request, scope, realm string, cfg *pb.IcConfig, secrets *pb.IcSecrets, tx storage.Tx) (*ga4gh.Identity, int, error) {
	token, status, err := s.getTokenIdentity(tok, scope, getClientID(r), isUserInfo(r), tx)
	if err != nil {
		return token, status, err
	}
	return s.getTokenAccountIdentity(s.ctx, token, realm, cfg, secrets, tx)
}

func (s *Service) refreshTokenToIdentity(tok string, r *http.Request, cfg *pb.IcConfig, secrets *pb.IcSecrets, tx storage.Tx) (*ga4gh.Identity, int, error) {
	id, status, err := s.getTokenIdentity(tok, "", getClientID(r), isUserInfo(r), tx)
	if err != nil {
		return nil, status, fmt.Errorf("inspecting token: %v", err)
	}
	token := pb.TokenMetadata{}
	if err := s.store.ReadTx(storage.TokensDatatype, getRealm(r), id.Subject, id.ID, storage.LatestRev, &token, tx); err != nil {
		if storage.ErrNotFound(err) {
			return nil, http.StatusBadRequest, fmt.Errorf("the incoming refresh token had already been revoked or is invalid")
		}
		return nil, http.StatusServiceUnavailable, err
	}
	return s.getTokenAccountIdentity(s.ctx, id, getRealm(r), cfg, secrets, tx)
}

func (s *Service) accountToIdentity(ctx context.Context, acct *pb.Account, cfg *pb.IcConfig, secrets *pb.IcSecrets) (*ga4gh.Identity, error) {
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
		tags := s.permissions.IncludeTags(subject, email, link.Tags, cfg.AccountTags)
		if len(tags) == 0 {
			tags = []string{"IC"}
		}
		identities[email] = tags
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

func (s *Service) loginTokenToIdentity(acTok, idTok string, idp *pb.IdentityProvider, r *http.Request, cfg *pb.IcConfig, secrets *pb.IcSecrets) (*ga4gh.Identity, int, error) {
	t, err := s.getIssuerTranslator(s.ctx, idp.Issuer, cfg, secrets)
	if err != nil {
		return nil, http.StatusUnauthorized, err
	}

	if len(acTok) > 0 && s.idpProvidesPassports(idp) {
		tid, err := t.TranslateToken(s.ctx, acTok)
		if err != nil {
			return nil, http.StatusUnauthorized, fmt.Errorf("translating access token from issuer %q: %v", idp.Issuer, err)
		}
		if !common.HasUserinfoClaims(tid) {
			return tid, http.StatusOK, nil
		}
		id, err := translator.FetchUserinfoClaims(s.ctx, acTok, idp.Issuer, tid.Subject, t)
		if err != nil {
			return nil, http.StatusUnauthorized, fmt.Errorf("fetching user info from issuer %q: %v", idp.Issuer, err)
		}
		return id, http.StatusOK, nil
	}
	if len(idTok) > 0 {
		// Assumes the login ID token is a JWT containing standard claims.
		tid, err := t.TranslateToken(s.ctx, idTok)
		if err != nil {
			return nil, http.StatusUnauthorized, fmt.Errorf("translating ID token from issuer %q: %v", idp.Issuer, err)
		}
		return tid, http.StatusOK, nil
	}
	return nil, http.StatusBadRequest, fmt.Errorf("fetching identity: the IdP is not configured to fetch passports and the IdP did not provide an ID token")
}

func (s *Service) idpProvidesPassports(idp *pb.IdentityProvider) bool {
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

func (s *Service) accountLinkToClaims(ctx context.Context, acct *pb.Account, subject string, cfg *pb.IcConfig, secrets *pb.IcSecrets) (map[string][]ga4gh.OldClaim, error) {
	id := &ga4gh.Identity{
		GA4GH: make(map[string][]ga4gh.OldClaim),
	}
	link, _ := findLinkedAccount(acct, subject)
	if link == nil {
		return id.GA4GH, nil
	}
	ttl := getDurationOption(cfg.Options.ClaimTtlCap, descClaimTtlCap)
	if err := s.populateLinkVisas(ctx, id, link, ttl, cfg, secrets); err != nil {
		return nil, err
	}

	return id.GA4GH, nil
}

func linkedIdentityValue(sub, iss string) string {
	sub = url.QueryEscape(sub)
	iss = url.QueryEscape(iss)
	return fmt.Sprintf("%s,%s", sub, iss)
}

func (s *Service) addLinkedIdentities(id *ga4gh.Identity, link *pb.ConnectedAccount, privateKey *rsa.PrivateKey, cfg *pb.IcConfig) error {
	if len(id.Subject) == 0 {
		return nil
	}

	subjectIssuers := map[string]bool{}
	now := time.Now().Unix()

	// TODO: add config option for LinkedIdentities expiry.
	exp := id.Expiry

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
			Issuer:    s.getIssuerString(),
			IssuedAt:  now,
			ExpiresAt: exp,
		},
		Scope: "openid",
		Assertion: ga4gh.Assertion{
			Type:     ga4gh.LinkedIdentities,
			Asserted: int64(link.Refreshed),
			Value:    ga4gh.Value(strings.Join(linked, ";")),
			Source:   ga4gh.Source(s.getIssuerString()),
		},
	}

	v, err := ga4gh.NewVisaFromData(d, ga4gh.RS256, privateKey, keyID)
	if err != nil {
		return fmt.Errorf("ga4gh.NewVisaFromData(_) failed: %v", err)
	}

	id.VisaJWTs = append(id.VisaJWTs, string(v.JWT()))
	return nil
}

func (s *Service) populateLinkVisas(ctx context.Context, id *ga4gh.Identity, link *pb.ConnectedAccount, ttl time.Duration, cfg *pb.IcConfig, secrets *pb.IcSecrets) error {
	passport := link.Passport
	if passport == nil {
		passport = &cpb.Passport{}
	}
	jwts, err := s.decryptEmbeddedTokens(ctx, passport.InternalEncryptedVisas)
	if err != nil {
		return err
	}

	priv, err := s.privateKeyFromSecrets(s.getIssuerString(), secrets)
	if err != nil {
		return err
	}

	id.VisaJWTs = append(id.VisaJWTs, jwts...)

	if err = s.addLinkedIdentities(id, link, priv, cfg); err != nil {
		return fmt.Errorf("add linked identities to visas failed: %v", err)
	}

	return nil
}

func findSimilarClaim(claims []ga4gh.OldClaim, match *ga4gh.OldClaim) *ga4gh.OldClaim {
	for _, c := range claims {
		if c.Value == match.Value && c.Source == match.Source && c.By == match.By && conditionEqual(c.Condition, match.Condition) {
			return &c
		}
	}
	return nil
}

func conditionEqual(a, b map[string]ga4gh.OldClaimCondition) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return reflect.DeepEqual(a, b)
}

func getBearerToken(r *http.Request) string {
	tok := common.GetParam(r, "access_token")
	if len(tok) > 0 {
		return tok
	}
	parts := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
		return parts[1]
	}
	return ""
}

func getScope(r *http.Request) (string, error) {
	s := common.GetParam(r, "scope")
	if !hasScopes(scopeOpenID, s, matchFullScope) {
		return "", fmt.Errorf("scope must include 'openid'")
	}
	return s, nil
}

func filterScopes(scope string, filter map[string]bool) string {
	parts := strings.Split(scope, " ")
	out := []string{}
	for _, p := range parts {
		baseScope := strings.Split(p, ":")[0]
		if _, ok := filter[baseScope]; ok {
			out = append(out, p)
		}
	}
	return strings.Join(out, " ")
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

func scopedIdentity(identity *ga4gh.Identity, scope, iss, subject, nonce string, iat, nbf, exp int64, aud []string, azp string) *ga4gh.Identity {
	claims := &ga4gh.Identity{
		Issuer:           iss,
		Subject:          subject,
		Audiences:        ga4gh.Audiences(aud),
		IssuedAt:         iat,
		NotBefore:        nbf,
		ID:               common.GenerateGUID(),
		AuthorizedParty:  azp,
		Expiry:           exp,
		Scope:            scope,
		IdentityProvider: identity.IdentityProvider,
		Nonce:            nonce,
	}
	if !hasScopes("refresh", scope, matchFullScope) {
		// TODO: remove this extra "ga4gh" check once DDAP is compatible.
		if hasScopes("identities", scope, matchFullScope) || hasScopes(passportScope, scope, matchFullScope) || hasScopes(ga4ghScope, scope, matchFullScope) {
			claims.Identities = identity.Identities
		}
		if hasScopes("profile", scope, matchFullScope) {
			claims.Name = identity.Name
			claims.FamilyName = identity.FamilyName
			claims.GivenName = identity.GivenName
			claims.Username = identity.Username
			claims.Picture = identity.Picture
			claims.Locale = identity.Locale
			claims.Email = identity.Email
			claims.Picture = identity.Picture
		}
	}

	return claims
}

type authToken struct {
	ID       string `json:"jti,omitempty"`
	IssuedAt int64  `json:"iat,omitempty"`
	Expiry   int64  `json:"exp,omitempty"`
}

// Valid implements dgrijalva/jwt-go Claims interface. This will be called when using
// dgrijalva/jwt-go parse. This validates only the exp timestamp.
func (auth *authToken) Valid() error {
	now := time.Now().Unix()
	if now > auth.Expiry {
		return fmt.Errorf("token is expired")
	}
	return nil
}

func (s *Service) createAuthToken(subject, scope, provider, realm, nonce string, now time.Time, cfg *pb.IcConfig, tx storage.Tx) (string, error) {
	ttl := getDurationOption(cfg.Options.AuthCodeTokenTtl, descAuthCodeTokenTTL)
	token := &authToken{
		ID:     common.GenerateGUID(),
		Expiry: now.Add(ttl).Unix(),
	}
	tokenMetadata := &pb.TokenMetadata{
		TokenType:        "code",
		IssuedAt:         now.Unix(),
		Scope:            scope,
		IdentityProvider: provider,
		Subject:          subject,
		Nonce:            nonce,
	}
	err := s.store.WriteTx(storage.AuthCodeDatatype, realm, storage.DefaultUser, token.ID, storage.LatestRev, tokenMetadata, nil, tx)
	if err != nil {
		return "", fmt.Errorf("writing refresh token metadata to storage: %v", err)
	}
	priv, err := s.getIssuerPrivateKey(s.getIssuerString(), tx)
	if err != nil {
		return "", err
	}
	jot := jwt.NewWithClaims(jwt.SigningMethodRS256, token)
	// TODO: should set key id properly and sync with JWKS.
	jot.Header[keyID] = keyID
	return jot.SignedString(priv)
}

func (s *Service) createToken(identity *ga4gh.Identity, scope, aud, azp, realm, nonce string, now time.Time, ttl time.Duration, cfg *pb.IcConfig, tx storage.Tx) (string, error) {
	subject := identity.Subject
	iss := s.getIssuerString()
	exp := now.Add(ttl)
	var audiences []string
	if aud == "" || hasScopes("link", scope, matchPrefixScope) {
		// This token is designed to be ONLY consumed by the IC itself.
		audiences = append(audiences, iss)
	} else {
		audiences = append(audiences, aud)
		// TODO: we will change the token flow in phase 2, after that we just set the DAM needed to be audience here.
		for name, client := range cfg.Clients {
			if strings.HasPrefix(name, "ga4gh_") {
				audiences = append(audiences, client.ClientId)
			}
		}
		if hasScopes("account_admin", scope, matchFullScope) {
			audiences = append(audiences, iss)
		}
	}
	priv, err := s.getIssuerPrivateKey(iss, tx)
	if err != nil {
		return "", err
	}

	claims := scopedIdentity(identity, scope, iss, subject, nonce, now.Unix(), now.Add(-1*time.Minute).Unix(), exp.Unix(), audiences, azp)
	claims.Realm = realm

	jot := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	// TODO: should set key id properly and sync with JWKS.
	jot.Header[keyID] = keyID
	token, err := jot.SignedString(priv)
	if err != nil {
		return "", err
	}

	if hasScopes("refresh", scope, matchFullScope) {
		tokenMetadata := &pb.TokenMetadata{
			TokenType:        "refresh",
			IssuedAt:         claims.IssuedAt,
			Scope:            claims.Scope,
			IdentityProvider: claims.IdentityProvider,
		}
		err := s.store.WriteTx(storage.TokensDatatype, realm, claims.Subject, claims.ID, storage.LatestRev, tokenMetadata, nil, tx)
		if err != nil {
			return "", fmt.Errorf("writing refresh token metadata to storage: %v", err)
		}
	}

	return token, nil
}

func (s *Service) createTokens(identity *ga4gh.Identity, includeRefresh bool, r *http.Request, cfg *pb.IcConfig, tx storage.Tx) (*cpb.OidcTokenResponse, error) {
	now := time.Now()
	ttl := common.GetParam(r, "ttl")
	if len(ttl) == 0 {
		ttl = cfg.Options.DefaultPassportTokenTtl
	}
	duration := getDurationOption(ttl, descDefaultPassportTokenTTL)
	maxTTL := getDurationOption(cfg.Options.MaxPassportTokenTtl, descMaxPassportTokenTTL)
	if duration > maxTTL {
		duration = maxTTL
	}

	clientID := getClientID(r)
	realm := getRealm(r)
	accessTok, err := s.createToken(identity, filterScopes(identity.Scope, filterAccessTokScope), clientID, clientID, realm, noNonce, now, duration, cfg, tx)
	if err != nil {
		return nil, fmt.Errorf("creating access token: %v", err)
	}
	idTok, err := s.createToken(identity, filterScopes(identity.Scope, filterIDTokScope), clientID, clientID, realm, identity.Nonce, now, duration, cfg, tx)
	if err != nil {
		return nil, fmt.Errorf("creating id token: %v", err)
	}
	refreshTok := ""
	if includeRefresh {
		if refreshTok, err = s.createToken(identity, "refresh "+identity.Scope, "", "", realm, noNonce, now, getDurationOption(cfg.Options.RefreshTokenTtl, descRefreshTokenTTL), cfg, tx); err != nil {
			return nil, fmt.Errorf("creating refresh token: %v", err)
		}
	}

	return &cpb.OidcTokenResponse{
		AccessToken:  accessTok,
		IdToken:      idTok,
		RefreshToken: refreshTok,
		TokenType:    "bearer",
		ExpiresIn:    int32(duration.Seconds()),
		Uid:          common.GenerateGUID(),
	}, nil
}

func (s *Service) getIssuerString() string {
	return s.getDomainURL() + "/oidc"
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

func getClient(cfg *pb.IcConfig, r *http.Request) *pb.Client {
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

func matchRedirect(client *pb.Client, redirect string) bool {
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

func (s *Service) newAccountWithLink(ctx context.Context, linkID *ga4gh.Identity, provider string, cfg *pb.IcConfig) (*pb.Account, error) {
	now := common.GetNowInUnixNano()
	genlen := getIntOption(cfg.Options.AccountNameLength, descAccountNameLength)
	accountPrefix := "ic_"
	genlen -= len(accountPrefix)
	subject := accountPrefix + strings.Replace(common.GenerateGUID(), "-", "", -1)[:genlen]

	acct := &pb.Account{
		Revision:          0,
		Profile:           setupAccountProfile(linkID),
		Properties:        setupAccountProperties(linkID, subject, now, now),
		ConnectedAccounts: make([]*pb.ConnectedAccount, 0),
		State:             "ACTIVE",
		Ui:                make(map[string]string),
	}
	err := s.populateAccountClaims(ctx, acct, linkID, provider)
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

func (s *Service) populateAccountClaims(ctx context.Context, acct *pb.Account, id *ga4gh.Identity, provider string) error {
	link, _ := findLinkedAccount(acct, id.Subject)
	now := common.GetNowInUnixNano()
	if link == nil {
		link = &pb.ConnectedAccount{
			Profile:      setupAccountProfile(id),
			Properties:   setupAccountProperties(id, id.Subject, now, now),
			Provider:     provider,
			Refreshed:    now,
			Revision:     1,
			LinkRevision: 1,
		}
		acct.ConnectedAccounts = append(acct.ConnectedAccounts, link)
	} else {
		// TODO: refresh some account profile attributes.
		link.Refreshed = now
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

func setupAccountProfile(id *ga4gh.Identity) *pb.AccountProfile {
	return &pb.AccountProfile{
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

func setupAccountProperties(id *ga4gh.Identity, subject string, created, modified float64) *pb.AccountProperties {
	return &pb.AccountProperties{
		Subject:       subject,
		Email:         id.Email,
		EmailVerified: id.EmailVerified,
		Created:       created,
		Modified:      modified,
	}
}

func claimsAreEqual(a, b map[string][]ga4gh.OldClaim) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, ok := b[k]
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := 0; i < len(av); i++ {
			if reflect.DeepEqual(av[i], bv[i]) {
				continue
			}
			found := false
			for j := 0; j < len(bv); j++ {
				if i != j && reflect.DeepEqual(av[i], bv[j]) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}
	return true
}

func findLinkedAccount(acct *pb.Account, subject string) (*pb.ConnectedAccount, int) {
	if acct.ConnectedAccounts == nil {
		return nil, -1
	}
	for i, link := range acct.ConnectedAccounts {
		if link.Properties.Subject == subject {
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
	var cfgIdp *pb.IdentityProvider
	for _, idp := range cfg.IdentityProviders {
		if idp.Issuer == issuer {
			cfgIdp = idp
			break
		}
	}
	if cfgIdp == nil {
		return nil, fmt.Errorf("passport issuer not found %q", issuer)
	}
	t, err = s.createIssuerTranslator(s.ctx, cfgIdp, secrets)
	if err != nil {
		return nil, fmt.Errorf("failed to create translator for issuer %q: %v", issuer, err)
	}
	s.translators.Store(issuer, t)
	return t, err
}

func (s *Service) createIssuerTranslator(ctx context.Context, cfgIdp *pb.IdentityProvider, secrets *pb.IcSecrets) (translator.Translator, error) {
	iss := cfgIdp.Issuer
	publicKey := ""
	k, ok := secrets.TokenKeys[iss]
	if ok {
		publicKey = k.PublicKey
	}

	selfIssuer := s.getIssuerString()
	signingPrivateKey := ""
	k, ok = secrets.TokenKeys[selfIssuer]
	if ok {
		signingPrivateKey = k.PrivateKey
	}

	return translator.CreateTranslator(ctx, iss, cfgIdp.TranslateUsing, cfgIdp.ClientId, publicKey, selfIssuer, signingPrivateKey)
}

func (s *Service) checkConfigIntegrity(cfg *pb.IcConfig) error {
	// Check Id Providers.
	for name, idp := range cfg.IdentityProviders {
		if err := common.CheckName("name", name, nil); err != nil {
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
		if _, err := common.CheckUI(idp.Ui, true); err != nil {
			return fmt.Errorf("identity provider %q: %v", name, err)
		}
	}

	// Check Clients.
	for name, client := range cfg.Clients {
		if err := common.CheckName("name", name, nil); err != nil {
			return fmt.Errorf("invalid client name %q: %v", name, err)
		}
		if len(client.ClientId) == 0 {
			return fmt.Errorf("client %q is missing a client ID", name)
		}
		for i, uri := range client.RedirectUris {
			if strings.HasPrefix(uri, "/") {
				continue
			}
			if err := validateURLs(map[string]string{
				fmt.Sprintf("client '%s' redirect URI %d", name, i+1): uri,
			}); err != nil {
				return err
			}
		}
		if _, err := common.CheckUI(client.Ui, true); err != nil {
			return fmt.Errorf("client %q: %v", name, err)
		}
	}

	for name, at := range cfg.AccountTags {
		if err := common.CheckName(tagField, name, tagNameCheck); err != nil {
			return fmt.Errorf("invalid account tag name %q: %v", name, err)
		}

		if _, err := common.CheckUI(at.Ui, true); err != nil {
			return fmt.Errorf("account tag %q: %v", name, err)
		}
	}

	// Check Options.
	opts := makeConfigOptions(cfg.Options)
	descs := common.ToCommonDescriptors(opts.ComputedDescriptors)
	if err := common.CheckIntOption(opts.AccountNameLength, "accountNameLength", descs); err != nil {
		return err
	}
	if err := common.CheckStringListOption(opts.WhitelistedRealms, "whitelistedRealms", descs); err != nil {
		return err
	}
	if err := common.CheckStringOption(opts.DefaultPassportTokenTtl, "defaultPassportTokenTtl", descs); err != nil {
		return err
	}
	if err := common.CheckStringOption(opts.MaxPassportTokenTtl, "maxPassportTokenTtl", descs); err != nil {
		return err
	}
	if err := common.CheckStringOption(opts.AuthCodeTokenTtl, "authCodeTokenTtl", descs); err != nil {
		return err
	}
	if err := common.CheckStringOption(opts.AccessTokenTtl, "accessTokenTtl", descs); err != nil {
		return err
	}
	if err := common.CheckStringOption(opts.RefreshTokenTtl, "refreshTokenTtl", descs); err != nil {
		return err
	}
	if err := common.CheckStringOption(opts.ClaimTtlCap, "claimTtlCap", descs); err != nil {
		return err
	}
	dpTTL := getDurationOption(opts.DefaultPassportTokenTtl, descDefaultPassportTokenTTL)
	mpTTL := getDurationOption(opts.MaxPassportTokenTtl, descMaxPassportTokenTTL)
	if dpTTL > mpTTL {
		return fmt.Errorf("defaultPassportTtl (%s) must not be greater than maxPassportTtl (%s)", dpTTL, mpTTL)
	}

	if _, err := common.CheckUI(cfg.Ui, true); err != nil {
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
	out.ComputedDescriptors = map[string]*pb.ConfigOptions_Descriptor{
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

func makeIdentityProvider(idp *pb.IdentityProvider) *pb.IdentityProvider {
	return &pb.IdentityProvider{
		Issuer: idp.Issuer,
		Ui:     idp.Ui,
	}
}

func (s *Service) makeAccount(ctx context.Context, acct *pb.Account, cfg *pb.IcConfig, secrets *pb.IcSecrets) *pb.Account {
	out := &pb.Account{}
	proto.Merge(out, acct)
	out.State = ""
	out.ConnectedAccounts = []*pb.ConnectedAccount{}
	for _, ca := range acct.ConnectedAccounts {
		out.ConnectedAccounts = append(out.ConnectedAccounts, s.makeConnectedAccount(ctx, ca, cfg, secrets))
	}
	return out
}

func (s *Service) makeConnectedAccount(ctx context.Context, ca *pb.ConnectedAccount, cfg *pb.IcConfig, secrets *pb.IcSecrets) *pb.ConnectedAccount {
	out := &pb.ConnectedAccount{}
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

func (s *Service) loadAccount(name, realm string, tx storage.Tx) (*pb.Account, int, error) {
	acct := &pb.Account{}
	status, err := s.singleRealmReadTx(storage.AccountDatatype, realm, storage.DefaultUser, name, storage.LatestRev, acct, tx)
	if err != nil {
		return nil, status, err
	}
	if acct.State != "ACTIVE" {
		return nil, http.StatusNotFound, fmt.Errorf("not found")
	}
	return acct, http.StatusOK, nil
}

func (s *Service) lookupAccount(fedAcct, realm string, tx storage.Tx) (*pb.Account, int, error) {
	lookup, err := s.accountLookup(realm, fedAcct, tx)
	if err != nil {
		return nil, http.StatusServiceUnavailable, err
	}
	if lookup == nil {
		return nil, http.StatusNotFound, fmt.Errorf("subject not found")
	}
	return s.loadAccount(lookup.Subject, realm, tx)
}

func (s *Service) saveNewLinkedAccount(newAcct *pb.Account, id *ga4gh.Identity, desc string, r *http.Request, tx storage.Tx, lookup *pb.AccountLookup) error {
	if err := s.saveAccount(nil, newAcct, desc, r, id.Subject, tx); err != nil {
		return fmt.Errorf("service dependencies not available; try again later")
	}
	rev := int64(0)
	if lookup != nil {
		rev = lookup.Revision
	}
	lookup = &pb.AccountLookup{
		Subject:  newAcct.Properties.Subject,
		Revision: rev,
		State:    "ACTIVE",
	}
	if err := s.saveAccountLookup(lookup, getRealm(r), id.Subject, r, id, tx); err != nil {
		return fmt.Errorf("service dependencies not available; try again later")
	}
	return nil
}

func validateURLs(input map[string]string) error {
	for k, v := range input {
		if !common.IsURL(v) {
			return fmt.Errorf("%q value %q is not a URL", k, v)
		}
	}
	return nil
}

func getDuration(d string, def time.Duration) time.Duration {
	out, err := common.ParseDuration(d, def)
	if err != nil {
		return def
	}
	return out
}

func getDurationOption(d string, desc *pb.ConfigOptions_Descriptor) time.Duration {
	if desc == nil || len(desc.DefaultValue) == 0 {
		return getDuration(d, noDuration)
	}
	defVal, err := common.ParseDuration(desc.DefaultValue, noDuration)
	if err != nil || defVal == 0 {
		return getDuration(d, noDuration)
	}
	return getDuration(d, defVal)
}

func getIntOption(val int32, desc *pb.ConfigOptions_Descriptor) int {
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

	return cfg, nil
}

func (s *Service) saveConfig(cfg *pb.IcConfig, desc, resType string, r *http.Request, id *ga4gh.Identity, orig, update proto.Message, modification *pb.ConfigModification, tx storage.Tx) error {
	if modification != nil && modification.DryRun {
		return nil
	}
	cfg.Revision++
	cfg.CommitTime = common.GetNowInUnixNano()
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

func (s *Service) getIssuerKeys(iss string, tx storage.Tx) (*pb.IcSecrets_TokenKeys, error) {
	secrets, err := s.loadSecrets(tx)
	if err != nil {
		return nil, fmt.Errorf("error loading secrets: %v", err)
	}
	k, ok := secrets.TokenKeys[iss]
	if !ok {
		return nil, fmt.Errorf("token keys not found for passport issuer %q", iss)
	}
	return k, nil
}

func (s *Service) getIssuerPublicKey(iss string, tx storage.Tx) (*rsa.PublicKey, error) {
	k, err := s.getIssuerKeys(iss, tx)
	if err != nil {
		// TODO: Use OIDC JWKS to look up the public key.
		return nil, fmt.Errorf("fetching public key for issuer %q: %v", iss, err)
	}
	block, _ := pem.Decode([]byte(k.PublicKey))
	pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key for issuer %q: %v", iss, err)
	}
	return pub, nil
}

func (s *Service) getIssuerPrivateKey(iss string, tx storage.Tx) (*rsa.PrivateKey, error) {
	k, err := s.getIssuerKeys(iss, tx)
	if err != nil {
		return nil, fmt.Errorf("fetching private key for issuer %q: %v", iss, err)
	}
	block, _ := pem.Decode([]byte(k.PrivateKey))
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing private key for issuer %q: %v", iss, err)
	}
	return priv, nil
}

func (s *Service) privateKeyFromSecrets(iss string, secrets *pb.IcSecrets) (*rsa.PrivateKey, error) {
	k, ok := secrets.TokenKeys[iss]
	if !ok {
		return nil, fmt.Errorf("token keys not found for passport issuer %q", iss)
	}
	block, _ := pem.Decode([]byte(k.PrivateKey))
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing private key for issuer %q: %v", iss, err)
	}
	return priv, nil
}

func (s *Service) saveSecrets(secrets *pb.IcSecrets, desc, resType string, r *http.Request, id *ga4gh.Identity, tx storage.Tx) error {
	secrets.Revision++
	secrets.CommitTime = float64(time.Now().UnixNano()) / 1e9
	if err := s.store.WriteTx(storage.SecretsDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, secrets.Revision, secrets, storage.MakeConfigHistory(desc, resType, secrets.Revision, secrets.CommitTime, r, id.Subject, nil, nil), tx); err != nil {
		return fmt.Errorf("service storage unavailable: %v, retry later", err)
	}
	return nil
}

func (s *Service) accountLookup(realm, acct string, tx storage.Tx) (*pb.AccountLookup, error) {
	lookup := &pb.AccountLookup{}
	status, err := s.singleRealmReadTx(storage.AccountLookupDatatype, realm, storage.DefaultUser, acct, storage.LatestRev, lookup, tx)
	if err != nil && status == http.StatusNotFound {
		return nil, nil
	}
	return lookup, err
}

func (s *Service) saveAccountLookup(lookup *pb.AccountLookup, realm, fedAcct string, r *http.Request, id *ga4gh.Identity, tx storage.Tx) error {
	lookup.Revision++
	lookup.CommitTime = common.GetNowInUnixNano()
	if err := s.store.WriteTx(storage.AccountLookupDatatype, realm, storage.DefaultUser, fedAcct, lookup.Revision, lookup, storage.MakeConfigHistory("link account", storage.AccountLookupDatatype, lookup.Revision, lookup.CommitTime, r, id.Subject, nil, lookup), tx); err != nil {
		return fmt.Errorf("service storage unavailable: %v, retry later", err)
	}
	return nil
}

func (s *Service) removeAccountLookup(rev int64, realm, fedAcct string, r *http.Request, id *ga4gh.Identity, tx storage.Tx) error {
	lookup := &pb.AccountLookup{
		Subject:  "",
		Revision: rev,
		State:    "DELETED",
	}
	if err := s.saveAccountLookup(lookup, realm, fedAcct, r, id, tx); err != nil {
		return err
	}
	return nil
}

func (s *Service) saveAccount(oldAcct, newAcct *pb.Account, desc string, r *http.Request, subject string, tx storage.Tx) error {
	newAcct.Revision++
	newAcct.Properties.Modified = common.GetNowInUnixNano()
	if newAcct.Properties.Created == 0 {
		if oldAcct != nil && oldAcct.Properties.Created != 0 {
			newAcct.Properties.Created = oldAcct.Properties.Created
		} else {
			newAcct.Properties.Created = newAcct.Properties.Modified
		}
	}

	if err := s.store.WriteTx(storage.AccountDatatype, getRealm(r), storage.DefaultUser, newAcct.Properties.Subject, newAcct.Revision, newAcct, storage.MakeConfigHistory(desc, storage.AccountDatatype, newAcct.Revision, newAcct.Properties.Modified, r, subject, oldAcct, newAcct), tx); err != nil {
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

func isLookupActive(lookup *pb.AccountLookup) bool {
	return lookup != nil && lookup.State == "ACTIVE"
}

func normalizeConfig(cfg *pb.IcConfig) error {
	return nil
}

type damArgs struct {
	clientId     string
	clientSecret string
	persona      string
}

// ImportFiles ingests bootstrap configuration files to the IC's storage sytem.
func (s *Service) ImportFiles(importType string) error {
	wipe := false
	switch importType {
	case "AUTO_RESET":
		cfg, err := s.loadConfig(nil, storage.DefaultRealm)
		if err != nil {
			if !storage.ErrNotFound(err) {
				wipe = true
			}
		} else if err := s.checkConfigIntegrity(cfg); err != nil {
			wipe = true
		}
	case "FORCE_WIPE":
		wipe = true
	}
	if wipe {
		glog.Infof("prepare for IC config import: wipe data store for all realms")
		if err := s.store.Wipe(storage.WipeAllRealms); err != nil {
			return err
		}
	}

	tx, err := s.store.Tx(true)
	if err != nil {
		return err
	}
	defer tx.Finish()

	ok, err := s.store.Exists(storage.SecretsDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}

	glog.Infof("import IC config into data store")
	history := &cpb.HistoryEntry{
		Revision:   1,
		User:       "admin",
		CommitTime: float64(time.Now().Unix()),
		Desc:       "Inital config",
	}
	info := s.store.Info()
	service := info["service"]
	path := info["path"]
	if service == "" || path == "" {
		return nil
	}
	fs := storage.NewFileStorage(service, path)

	cfg := &pb.IcConfig{}
	if err = fs.Read(storage.ConfigDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, cfg); err != nil {
		return err
	}
	history.Revision = cfg.Revision
	if err = s.store.WriteTx(storage.ConfigDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, cfg.Revision, cfg, history, tx); err != nil {
		return err
	}
	secrets := &pb.IcSecrets{}
	if err = fs.Read(storage.SecretsDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, secrets); err != nil {
		return err
	}
	history.Revision = secrets.Revision
	if err = s.store.WriteTx(storage.SecretsDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, secrets.Revision, secrets, history, tx); err != nil {
		return err
	}
	return nil
}

/////////////////////////////////////////////////////////
// OIDC related

// OidcWellKnownConfig handle OpenID Provider configuration request.
func (s *Service) OidcWellKnownConfig(w http.ResponseWriter, r *http.Request) {
	scopeSet := map[string]bool{}
	for k, v := range filterAccessTokScope {
		scopeSet[k] = v
	}
	for k, v := range filterIDTokScope {
		scopeSet[k] = v
	}
	scopes := []string{}
	for k := range scopeSet {
		scopes = append(scopes, k)
	}

	conf := &cpb.OidcConfig{
		Issuer:       s.getIssuerString(),
		JwksUri:      s.getDomainURL() + oidcJwksPath,
		AuthEndpoint: s.getDomainURL() + defaultAuthorizePath,
		ResponseTypesSupported: []string{
			"code",
		},
		TokenEndpoint:      s.getDomainURL() + defaultTokenPath,
		RevocationEndpoint: s.getDomainURL() + defaultRevocationPath,
		UserinfoEndpoint:   s.getDomainURL() + oidcUserInfoPath,
		ScopesSupported:    scopes,
	}
	common.SendResponse(conf, w)
}

// OidcKeys handle OpenID Provider jwks request.
func (s *Service) OidcKeys(w http.ResponseWriter, r *http.Request) {
	pub, err := s.getIssuerPublicKey(s.getIssuerString(), nil)
	if err != nil {
		glog.Infof("getIssuerPublicKey %q failed: %q", s.getIssuerString(), err)
		common.HandleError(http.StatusInternalServerError, err, w)
		return
	}

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       pub,
				Algorithm: "RS256",
				Use:       "sig",
				KeyID:     "kid",
			},
		},
	}

	data, err := json.Marshal(jwks)
	if err != nil {
		glog.Infof("Marshal failed: %q", err)
		common.HandleError(http.StatusInternalServerError, err, w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	common.AddCorsHeaders(w)
	w.Write(data)
}

// OidcUserInfo /oidc/userinfo handler
func (s *Service) OidcUserInfo(w http.ResponseWriter, r *http.Request) {
	tx, err := s.store.Tx(true)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	defer tx.Finish()

	realm, status, err := s.tokenRealm(r)
	if err != nil {
		common.HandleError(status, err, w)
	}

	cfg, err := s.loadConfig(tx, realm)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}

	secrets, err := s.loadSecrets(tx)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}

	id, status, err := s.getIdentity(r, "", realm, cfg, secrets, tx)
	if err != nil {
		common.HandleError(status, err, w)
		return
	}

	// TODO: should also check the client id of access token is same as request client id.

	// scope down identity information based on the token scope.
	claims := scopedIdentity(id, id.Scope, id.Issuer, id.Subject, noNonce, id.IssuedAt, id.NotBefore, id.Expiry, nil, "")
	if hasScopes(passportScope, id.Scope, matchFullScope) || hasScopes(ga4ghScope, id.Scope, matchFullScope) {
		claims.VisaJWTs = id.VisaJWTs
	}

	data, err := json.Marshal(claims)
	if err != nil {
		glog.Infof("cannot encode user identity into JSON: %v", err)
		common.HandleError(http.StatusInternalServerError, err, w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	common.AddCorsHeaders(w)
	w.Write(data)
}
