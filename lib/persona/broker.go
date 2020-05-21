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

// Package persona provides a persona broker for use by clients.
package persona

import (
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/mux" /* copybara-comment */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"gopkg.in/square/go-jose.v2" /* copybara-comment */
	"github.com/dgrijalva/jwt-go" /* copybara-comment */
	"github.com/pborman/uuid" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/srcutil" /* copybara-comment: srcutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/strutil" /* copybara-comment: strutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */

	glog "github.com/golang/glog" /* copybara-comment */
	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	dampb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
	ipb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/ic/v1" /* copybara-comment: go_proto */
)

const (
	loginPageFile     = "pages/login.html"
	loginPageInfoFile = "pages/personas/login_info.html"
	staticDirectory   = "assets/serve/"
	serviceTitle      = "Persona Playground"
	loginInfoTitle    = "Persona Playground"
)

// Server is a fake OIDC passport broker service for a playground
// or test environment. Private keys are well-known and allows any
// user to act as system administrator.
// WARNING: ONLY for use with synthetic or test data.
//          Do not use unless you fully understand the security and privacy implications.
type Server struct {
	issuerURL     string
	key           *testkeys.Key
	cfg           *dampb.DamConfig
	Handler       *mux.Router
	loginPageTmpl *template.Template
}

// NewBroker returns a Persona Broker Server
func NewBroker(issuerURL string, key *testkeys.Key, service, path string, useOIDCPrefix bool) (*Server, error) {
	var cfg *dampb.DamConfig
	if len(service) > 0 && len(path) > 0 {
		cfg = &dampb.DamConfig{}
		store := storage.NewMemoryStorage(service, path)
		if err := store.ReadTx(storage.ConfigDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, cfg, nil); err != nil {
			return nil, err
		}
	}
	loginPageTmpl, err := httputils.TemplateFromFiles(loginPageFile, loginPageInfoFile)
	if err != nil {
		glog.Exitf("cannot create template for login page: %v", err)
	}

	s := &Server{
		issuerURL:     issuerURL,
		key:           key,
		cfg:           cfg,
		loginPageTmpl: loginPageTmpl,
	}

	r := mux.NewRouter()
	s.Handler = r
	registerHandlers(r, s, useOIDCPrefix)

	return s, nil
}

// Sign the jwt with the private key in Server.
func (s *Server) Sign(header map[string]string, claim jwt.Claims) (string, error) {
	jot := jwt.NewWithClaims(jwt.SigningMethodRS256, claim)

	for k, v := range header {
		jot.Header[k] = v
	}

	return jot.SignedString(s.key.Private)
}

// Config returns the DAM configuration currently in use.
func (s *Server) Config() *dampb.DamConfig {
	return s.cfg
}

func (s *Server) oidcWellKnownConfig(w http.ResponseWriter, r *http.Request) {
	conf := &cpb.OidcConfig{
		Issuer:           s.issuerURL,
		AuthEndpoint:     s.issuerURL + oidcAuthorizePath,
		TokenEndpoint:    s.issuerURL + oidcTokenPath,
		JwksUri:          s.issuerURL + oidcJwksPath,
		UserinfoEndpoint: s.issuerURL + oidcUserInfoPath,
	}

	if err := json.NewEncoder(w).Encode(conf); err != nil {
		glog.Infof("Marshal failed: %q", err)
	}
}

func (s *Server) oidcKeys(w http.ResponseWriter, r *http.Request) {
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       s.key.Public,
				Algorithm: "RS256",
				Use:       "sig",
				KeyID:     s.key.ID,
			},
		},
	}

	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		glog.Infof("Marshal failed: %q", err)
	}
}

func (s *Server) oidcUserInfo(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	parts := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		httputils.WriteError(w, status.Errorf(codes.PermissionDenied, "missing or invalid Authorization header"))
		return
	}
	token := parts[1]

	src, err := ga4gh.ConvertTokenToIdentityUnsafe(token)
	if err != nil {
		httputils.WriteError(w, status.Errorf(codes.PermissionDenied, "invalid Authorization token"))
		return
	}
	sub := src.Subject
	var persona *cpb.TestPersona
	var pname string
	for pn, p := range s.cfg.TestPersonas {
		if pn == sub || (p.Passport.StandardClaims != nil && p.Passport.StandardClaims["sub"] == sub) {
			pname = pn
			persona = p
			break
		}
	}
	if persona == nil {
		httputils.WriteError(w, status.Errorf(codes.PermissionDenied, "persona %q not found", sub))
		return
	}
	id, err := ToIdentity(pname, persona, "openid profile identities ga4gh_passport_v1 email", s.issuerURL)
	if err != nil {
		httputils.WriteError(w, status.Errorf(codes.PermissionDenied, "preparing persona %q: %v", sub, err))
		return
	}
	data, err := json.Marshal(id)
	if err != nil {
		httputils.WriteError(w, status.Errorf(codes.Internal, "cannot encode user identity %q into JSON: %v", sub, err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	httputils.WriteCorsHeaders(w)
	w.Write(data)
}

func (s *Server) oidcAuthorize(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	typ := httputils.QueryParam(r, "response_type")
	if typ != "code" {
		httputils.WriteError(w, status.Errorf(codes.InvalidArgument, "response type must be %q", "code"))
		return
	}

	redirect, err := url.QueryUnescape(r.URL.Query().Get("redirect_uri"))
	if err != nil {
		httputils.WriteError(w, status.Errorf(codes.InvalidArgument, "redirect_uri must be a valid URL: %v", err))
		return
	}
	if redirect == "" {
		httputils.WriteError(w, status.Errorf(codes.InvalidArgument, "redirect_uri must be specified"))
		return
	}
	u, err := url.Parse(redirect)
	if err != nil {
		httputils.WriteError(w, status.Errorf(codes.NotFound, "invalid redirect_uri URL format: %v", err))
		return
	}

	state := httputils.QueryParam(r, "state")
	nonce := httputils.QueryParam(r, "nonce")
	clientID := httputils.QueryParam(r, "client_id")
	scope := httputils.QueryParam(r, "scope")

	loginHint := httputils.QueryParam(r, "login_hint")
	if len(loginHint) == 0 {
		s.sendLoginPage(u.String(), state, nonce, clientID, scope, w, r)
		return
	}

	pname := loginHint
	_, ok := s.cfg.TestPersonas[pname]
	if !ok {
		httputils.WriteError(w, status.Errorf(codes.NotFound, "persona %q not found", pname))
		return
	}

	code := pname
	if len(clientID) > 0 {
		code = code + "," + clientID
	}

	q := u.Query()
	q.Set("code", code)
	q.Set("scope", scope)
	q.Set("state", state)
	q.Set("nonce", nonce)
	u.RawQuery = q.Encode()
	httputils.WriteRedirect(w, r, u.String())
}

func (s *Server) sendLoginPage(redirect, state, nonce, clientID, scope string, w http.ResponseWriter, r *http.Request) {
	list := &ipb.LoginPageProviders{Personas: make(map[string]*ipb.LoginPageProviders_ProviderEntry)}

	for pname, p := range s.cfg.TestPersonas {
		ui := p.Ui
		if ui == nil {
			ui = make(map[string]string)
		}
		if _, ok := ui["label"]; !ok {
			ui["label"] = strutil.ToTitle(pname)
		}

		params := url.Values{}
		params.Add("login_hint", pname)
		params.Add("scope", scope)
		params.Add("redirect_uri", redirect)
		params.Add("state", state)
		params.Add("nonce=", nonce)
		params.Add("client_id", clientID)
		params.Add("response_type", "code")

		u, err := url.Parse(r.URL.String())
		if err != nil {
			httputils.WriteError(w, status.Errorf(codes.Internal, "%v", err))
			return
		}
		u.RawQuery = params.Encode()

		list.Personas[pname] = &ipb.LoginPageProviders_ProviderEntry{
			Url: u.String(),
			Ui:  ui,
		}
	}

	args := &loginPageArgs{
		ProviderList:   list,
		AssetDir:       "/static",
		ServiceTitle:   serviceTitle,
		LoginInfoTitle: loginInfoTitle,
	}

	if err := s.loginPageTmpl.Execute(w, args); err != nil {
		httputils.WriteError(w, status.Errorf(codes.Internal, "%v", err))
	}
}

type loginPageArgs struct {
	ProviderList   *ipb.LoginPageProviders
	AssetDir       string
	ServiceTitle   string
	LoginInfoTitle string
}

func basicAuthClientID(r *http.Request) string {
	auth := strings.SplitN(r.Header.Get("Authorization"), " ", 2)

	if len(auth) != 2 || auth[0] != "Basic" {
		return ""
	}

	payload, _ := base64.StdEncoding.DecodeString(auth[1])
	pair := strings.SplitN(string(payload), ":", 2)
	if len(pair) != 2 {
		return ""
	}

	return pair[0]
}

func (s *Server) oidcToken(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	clientID := httputils.QueryParam(r, "client_id")
	if len(clientID) == 0 {
		clientID = basicAuthClientID(r)
	}
	var code string
	switch httputils.QueryParam(r, "grant_type") {
	case "refresh_token":
		code = httputils.QueryParam(r, "refresh_token")
	default:
		code = httputils.QueryParam(r, "code")
	}
	parts := strings.SplitN(code, ",", 2)
	pname := parts[0]
	if len(parts) > 1 {
		clientID = parts[1]
	}
	persona, ok := s.cfg.TestPersonas[pname]
	if !ok {
		httputils.WriteError(w, status.Errorf(codes.NotFound, "persona %q not found", pname))
		return
	}
	acTok, _, err := NewAccessToken(pname, s.issuerURL, clientID, httputils.QueryParam(r, "scope"), persona)
	if err != nil {
		httputils.WriteError(w, status.Errorf(codes.Internal, "error creating access token for persona %q: %v", pname, err))
		return
	}
	refreshTok := pname
	if len(clientID) > 0 {
		refreshTok = pname + "," + clientID
	}
	resp := &cpb.OidcTokenResponse{
		AccessToken:  string(acTok),
		RefreshToken: refreshTok,
		TokenType:    "bearer",
		ExpiresIn:    60 * 60 * 24 * 365,
		Uid:          uuid.New(),
	}
	httputils.WriteResp(w, resp)
}

// TODO: move registeration of endpoints to main package.
func registerHandlers(r *mux.Router, s *Server, useOIDCPrefix bool) {
	if useOIDCPrefix {
		r.HandleFunc("/oidc"+oidcConfiguarePath, s.oidcWellKnownConfig)
		r.HandleFunc("/oidc"+oidcJwksPath, s.oidcKeys)
		r.HandleFunc("/oidc"+oidcAuthorizePath, s.oidcAuthorize)
		r.HandleFunc("/oidc"+oidcTokenPath, s.oidcToken)
		r.HandleFunc("/oidc"+oidcUserInfoPath, s.oidcUserInfo)
	} else {
		r.HandleFunc(oidcConfiguarePath, s.oidcWellKnownConfig)
		r.HandleFunc(oidcJwksPath, s.oidcKeys)
		r.HandleFunc(oidcAuthorizePath, s.oidcAuthorize)
		r.HandleFunc(oidcTokenPath, s.oidcToken)
		r.HandleFunc(oidcUserInfoPath, s.oidcUserInfo)
	}

	sfs := http.StripPrefix(staticFilePath, http.FileServer(http.Dir(srcutil.Path(staticDirectory))))
	r.PathPrefix(staticFilePath).Handler(sfs)
}
