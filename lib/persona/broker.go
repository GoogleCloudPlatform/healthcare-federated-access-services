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
	"fmt"
	"net/http"
	"net/url"
	"strings"

	glog "github.com/golang/glog" /* copybara-comment */
	"github.com/golang/protobuf/jsonpb" /* copybara-comment */
	"github.com/gorilla/mux" /* copybara-comment */
	"gopkg.in/square/go-jose.v2" /* copybara-comment */
	"github.com/dgrijalva/jwt-go" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common" /* copybara-comment: common */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/srcutil" /* copybara-comment: srcutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */
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
	issuerURL string
	key       *testkeys.Key
	cfg       *dampb.DamConfig
	Handler   *mux.Router
	loginPage string
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
	lp, err := srcutil.LoadFile(loginPageFile)
	if err != nil {
		glog.Fatalf("cannot load login page %q: %v", loginPageFile, err)
	}
	lpi, err := srcutil.LoadFile(loginPageInfoFile)
	if err != nil {
		glog.Fatalf("cannot load login page info %q: %v", loginPageInfoFile, err)
	}
	lp = strings.Replace(lp, "${LOGIN_INFO_HTML}", lpi, -1)

	s := &Server{
		issuerURL: issuerURL,
		key:       key,
		cfg:       cfg,
		loginPage: lp,
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
		httputil.HandleError(http.StatusUnauthorized, fmt.Errorf("missing or invalid Authorization header"), w)
		return
	}
	token := parts[1]

	src, err := common.ConvertTokenToIdentityUnsafe(token)
	if err != nil {
		httputil.HandleError(http.StatusUnauthorized, fmt.Errorf("invalid Authorization token"), w)
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
		httputil.HandleError(http.StatusUnauthorized, fmt.Errorf("persona %q not found", sub), w)
		return
	}
	id, err := ToIdentity(pname, persona, "openid profile identities ga4gh_passport_v1 email", s.issuerURL)
	if err != nil {
		httputil.HandleError(http.StatusUnauthorized, fmt.Errorf("preparing persona %q: %v", sub, err), w)
		return
	}
	data, err := json.Marshal(id)
	if err != nil {
		httputil.HandleError(http.StatusInternalServerError, fmt.Errorf("cannot encode user identity %q into JSON: %v", sub, err), w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	httputil.AddCorsHeaders(w)
	w.Write(data)
}

func (s *Server) oidcAuthorize(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	typ := httputil.GetParam(r, "response_type")
	if typ != "code" {
		httputil.HandleError(http.StatusBadRequest, fmt.Errorf("response type must be %q", "code"), w)
		return
	}

	redirect, err := url.QueryUnescape(r.URL.Query().Get("redirect_uri"))
	if err != nil {
		httputil.HandleError(http.StatusBadRequest, fmt.Errorf("redirect_uri must be a valid URL: %v", err), w)
		return
	}
	if redirect == "" {
		httputil.HandleError(http.StatusBadRequest, fmt.Errorf("redirect_uri must be specified"), w)
		return
	}
	u, err := url.Parse(redirect)
	if err != nil {
		httputil.HandleError(http.StatusNotFound, fmt.Errorf("invalid redirect_uri URL format: %v", err), w)
		return
	}

	state := httputil.GetParam(r, "state")
	nonce := httputil.GetParam(r, "nonce")
	clientID := httputil.GetParam(r, "client_id")
	scope := httputil.GetParam(r, "scope")

	loginHint := httputil.GetParam(r, "login_hint")
	if len(loginHint) == 0 {
		s.sendLoginPage(u.String(), state, nonce, clientID, scope, w, r)
		return
	}

	pname := loginHint
	_, ok := s.cfg.TestPersonas[pname]
	if !ok {
		httputil.HandleError(http.StatusNotFound, fmt.Errorf("persona %q not found", pname), w)
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
	httputil.SendRedirect(u.String(), r, w)
}

func (s *Server) sendLoginPage(redirect, state, nonce, clientID, scope string, w http.ResponseWriter, r *http.Request) {
	list := &ipb.LoginPageProviders{Personas: make(map[string]*ipb.LoginPageProviders_ProviderEntry)}

	for pname, p := range s.cfg.TestPersonas {
		ui := p.Ui
		if ui == nil {
			ui = make(map[string]string)
		}
		if _, ok := ui[common.UILabel]; !ok {
			ui[common.UILabel] = common.ToTitle(pname)
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
			httputil.HandleError(http.StatusInternalServerError, err, w)
			return
		}
		u.RawQuery = params.Encode()

		list.Personas[pname] = &ipb.LoginPageProviders_ProviderEntry{
			Url: u.String(),
			Ui:  ui,
		}
	}

	json, err := (&jsonpb.Marshaler{}).MarshalToString(list)
	if err != nil {
		httputil.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}

	page := strings.Replace(s.loginPage, "${PROVIDER_LIST}", json, -1)
	page = strings.Replace(page, "${ASSET_DIR}", "/static", -1)
	page = strings.Replace(page, "${SERVICE_TITLE}", serviceTitle, -1)
	page = strings.Replace(page, "${LOGIN_INFO_TITLE}", loginInfoTitle, -1)
	httputil.SendHTML(page, w)
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
	clientID := httputil.GetParam(r, "client_id")
	if len(clientID) == 0 {
		clientID = basicAuthClientID(r)
	}

	code := strings.Split(httputil.GetParam(r, "code"), ",")
	pname := code[0]
	if len(code) > 1 {
		clientID = code[1]
	}
	persona, ok := s.cfg.TestPersonas[pname]
	if !ok {
		httputil.HandleError(http.StatusNotFound, fmt.Errorf("persona %q not found", pname), w)
		return
	}
	acTok, _, err := NewAccessToken(pname, s.issuerURL, clientID, httputil.GetParam(r, "scope"), persona)
	if err != nil {
		httputil.HandleError(http.StatusInternalServerError, fmt.Errorf("error creating access token for persona %q: %v", pname, err), w)
		return
	}
	resp := &cpb.OidcTokenResponse{
		AccessToken: string(acTok),
		TokenType:   "bearer",
		ExpiresIn:   60 * 60 * 24 * 365,
		Uid:         common.GenerateGUID(),
	}
	httputil.SendResponse(resp, w)
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
