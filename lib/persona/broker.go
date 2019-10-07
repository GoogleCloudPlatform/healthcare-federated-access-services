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
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	glog "github.com/golang/glog"
	"github.com/golang/protobuf/jsonpb"
	"github.com/gorilla/mux"
	"gopkg.in/square/go-jose.v2"
	"github.com/dgrijalva/jwt-go"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys"
	dampb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1"
	ipb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/ic/v1"
)

const (
	oidcPrefix         = "/oidc"
	oidcWellKnownPath  = "/.well-known"
	oidcConfiguarePath = oidcWellKnownPath + "/openid-configuration"
	oidcJwksPath       = oidcWellKnownPath + "/jwks"
	oidcAuthorizePath  = "/authorize"
	oidcTokenPath      = "/token"
	oidcUserInfoPath   = "/userinfo"

	loginPageFile     = "pages/login.html"
	loginPageInfoFile = "pages/login-info-persona.html"
	serviceTitle      = "Persona Playground"
	loginInfoTitle    = "Persona Playground"
	assetPath         = "/static"
	staticFilePath    = assetPath + "/"
	staticDirectory   = "assets/static/"
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
func NewBroker(issuerURL string, key *testkeys.Key, service, path string) (*Server, error) {
	var cfg *dampb.DamConfig
	if len(service) > 0 && len(path) > 0 {
		cfg = &dampb.DamConfig{}
		store := storage.NewMemoryStorage(service, path)
		if err := store.ReadTx(storage.ConfigDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, cfg, nil); err != nil {
			return nil, err
		}
	}
	lp, err := common.LoadFile(loginPageFile)
	if err != nil {
		glog.Fatalf("cannot load login page %q: %v", loginPageFile, err)
	}
	lpi, err := common.LoadFile(loginPageInfoFile)
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
	r.HandleFunc(oidcPrefix+oidcConfiguarePath, s.oidcWellKnownConfig)
	r.HandleFunc(oidcPrefix+oidcJwksPath, s.oidcKeys)
	r.HandleFunc(oidcPrefix+oidcAuthorizePath, s.oidcAuthorize)
	r.HandleFunc(oidcPrefix+oidcTokenPath, s.oidcToken)
	r.HandleFunc(oidcPrefix+oidcUserInfoPath, s.oidcUserInfo)

	sfs := http.StripPrefix(staticFilePath, http.FileServer(http.Dir(filepath.Join(storage.ProjectRoot, staticDirectory))))
	r.PathPrefix(staticFilePath).Handler(sfs)

	s.Handler = r

	return s, nil
}

// Serve takes traffic.
func (s *Server) Serve(port string) {
	if len(port) == 0 {
		port = "8089"
	}
	glog.Infof("Persona Broker using port %v", port)
	glog.Fatal(http.ListenAndServe(":"+port, s.Handler))
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
	conf := &ipb.OidcConfig{
		Issuer:           s.issuerURL,
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
	token := common.GetParam(r, "access_token")
	if len(token) == 0 {
		parts := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			common.HandleError(http.StatusUnauthorized, fmt.Errorf("missing or invalid Authorization header"), w)
			return
		}
		token = parts[1]
	}
	src, err := common.ConvertTokenToIdentityUnsafe(token)
	if err != nil {
		common.HandleError(http.StatusUnauthorized, fmt.Errorf("invalid Authorization token"), w)
		return
	}
	sub := src.Subject
	var persona *dampb.TestPersona
	var pname string
	for pn, p := range s.cfg.TestPersonas {
		if pn == sub || (p.Passport.StandardClaims != nil && p.Passport.StandardClaims["sub"] == sub) {
			pname = pn
			persona = p
			break
		}
	}
	if persona == nil {
		common.HandleError(http.StatusUnauthorized, fmt.Errorf("persona %q not found", sub), w)
		return
	}
	id, err := PersonaToIdentity(pname, persona, "openid ga4gh_passport_v1", s.issuerURL)
	if err != nil {
		common.HandleError(http.StatusUnauthorized, fmt.Errorf("preparing persona %q: %v", sub, err), w)
		return
	}
	data, err := json.Marshal(id)
	if err != nil {
		common.HandleError(http.StatusInternalServerError, fmt.Errorf("cannot encode user identity %q into JSON: %v", sub, err), w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	common.AddCorsHeaders(w)
	w.Write(data)
}

func (s *Server) oidcAuthorize(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	typ := common.GetParam(r, "response_type")
	if typ != "code" {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("response type must be %q", "code"), w)
		return
	}
	redirect := common.GetParam(r, "redirect_uri")
	if redirect == "" {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("redirect_uri must be specified"), w)
		return
	}
	state := common.GetParam(r, "state")
	nonce := common.GetParam(r, "nonce")
	clientID := common.GetParam(r, "client_id")
	loginHint := common.GetParam(r, "login_hint")
	if len(loginHint) == 0 {
		s.sendLoginPage(redirect, state, nonce, clientID, w, r)
		return
	}
	pname := loginHint
	_, ok := s.cfg.TestPersonas[pname]
	if !ok {
		common.HandleError(http.StatusNotFound, fmt.Errorf("persona %q not found", pname), w)
		return
	}

	code := pname
	if len(clientID) > 0 {
		code = code + "," + clientID
	}

	u, err := url.Parse(redirect)
	if err != nil {
		common.HandleError(http.StatusNotFound, fmt.Errorf("invalid redirect URL format: %v", err), w)
		return
	}
	q := u.Query()
	q.Set("code", code)
	q.Set("state", state)
	q.Set("nonce", nonce)
	u.RawQuery = q.Encode()
	common.SendRedirect(u.String(), r, w)
}

func (s *Server) sendLoginPage(redirect, state, nonce, clientID string, w http.ResponseWriter, r *http.Request) {
	list := &ipb.LoginPageProviders{
		Personas: make(map[string]*ipb.LoginPageProviders_ProviderEntry),
	}
	path := common.RequestAbstractPath(r)
	for pname, p := range s.cfg.TestPersonas {
		ui := p.Ui
		if ui == nil {
			ui = make(map[string]string)
		}
		if _, ok := ui[common.UILabel]; !ok {
			ui[common.UILabel] = common.ToTitle(pname)
		}
		params := "?login_hint=" + url.QueryEscape(pname) + "&redirect_uri=" + url.QueryEscape(redirect) + "&state=" + url.QueryEscape(state) + "&nonce=" + url.QueryEscape(nonce) + "&client_id=" + url.QueryEscape(clientID) + "&response_type=code"
		list.Personas[pname] = &ipb.LoginPageProviders_ProviderEntry{
			Url: path + params,
			Ui:  ui,
		}
	}
	ma := jsonpb.Marshaler{}
	json, err := ma.MarshalToString(list)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	page := strings.Replace(s.loginPage, "${PROVIDER_LIST}", json, -1)
	page = strings.Replace(page, "${ASSET_DIR}", assetPath, -1)
	page = strings.Replace(page, "${SERVICE_TITLE}", serviceTitle, -1)
	page = strings.Replace(page, "${LOGIN_INFO_TITLE}", loginInfoTitle, -1)
	common.SendHTML(page, w)
}

func (s *Server) oidcToken(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	clientID := common.GetParam(r, "client_id")
	code := strings.Split(common.GetParam(r, "code"), ",")
	pname := code[0]
	if len(code) > 1 {
		clientID = code[1]
	}
	persona, ok := s.cfg.TestPersonas[pname]
	if !ok {
		common.HandleError(http.StatusNotFound, fmt.Errorf("persona %q not found", pname), w)
		return
	}
	acTok, _, err := PersonaAccessToken(pname, s.issuerURL, clientID, persona)
	if err != nil {
		common.HandleError(http.StatusInternalServerError, fmt.Errorf("error creating access token for persona %q: %v", pname, err), w)
		return
	}
	resp := &ipb.GetTokenResponse{
		AccessToken: string(acTok),
		TokenType:   "bearer",
		ExpiresIn:   60 * 60 * 24 * 365,
		Uid:         common.GenerateGUID(),
	}
	common.SendResponse(resp, w)
}
