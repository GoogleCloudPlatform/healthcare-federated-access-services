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
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/oauth2"
	"github.com/pborman/uuid"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/adapter"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage"

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1"
)

var (
	// viewPathRE is for resource name and view name lookup only.
	viewPathRE = regexp.MustCompile(`^resources/([^\s/]*)/views/([^\s/]*)$`)
	// rolePathRE is for resource name, view name and role name lookup only.
	rolePathRE = regexp.MustCompile(`^resources/([^\s/]*)/views/([^\s/]*)/roles/([^\s/]*)$`)
)

func extractBearerToken(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	if len(auth) == 0 {
		return "", fmt.Errorf("bearer token not found")
	}

	parts := strings.Split(auth, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return "", fmt.Errorf("token is not a bearer token")
	}

	return parts[1], nil
}

func extractAccessToken(r *http.Request) (string, error) {
	tok, err := extractBearerToken(r)
	if err == nil {
		return tok, nil
	}
	// TODO: access_token should not pass vai query.
	tok = r.URL.Query().Get("access_token")
	if len(tok) > 0 {
		return tok, nil
	}

	return "", fmt.Errorf("access token not found")
}

func extractAuthCode(r *http.Request) (string, error) {
	code := common.GetParam(r, "code")
	if len(code) != 0 {
		return code, nil
	}
	return "", fmt.Errorf("auth code not found")
}

func extractTTL(r *http.Request) (time.Duration, error) {
	str := r.URL.Query().Get("ttl")
	if len(str) == 0 {
		return defaultTTL, nil
	}

	ttl, err := common.ParseDuration(str, defaultTTL)
	if err != nil {
		return 0, fmt.Errorf("TTL parameter %q format error: %v", str, err)
	}
	if ttl == 0 {
		return defaultTTL, nil
	}
	if ttl < 0 || ttl > maxTTL {
		return 0, fmt.Errorf("TTL parameter %q out of range: must be positive and not exceed %s", str, maxTTLStr)
	}
	return ttl, nil
}

func responseKeyFile(r *http.Request) bool {
	return common.GetParam(r, "response_type") == "key-file-type"
}

// GetResourceToken implements endpoint "resources/{name}/views/{view}/token" or
// "resources/{name}/views/{view}/roles/{role}/token".
func (s *Service) GetResourceToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request method %s not allowed", r.Method), w)
		return
	}
	vars := mux.Vars(r)
	name := vars["name"]
	viewName := vars["view"]
	role := vars["role"]
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

	ttl, err := extractTTL(r)
	if err != nil {
		common.HandleError(http.StatusBadRequest, err, w)
		return
	}

	clientID := getClientID(r)
	status, err = s.checkAuthorization(id, ttl, name, viewName, grantRole, cfg, clientID, nil)
	if err != nil {
		common.HandleError(status, err, w)
		return
	}

	keyFile := responseKeyFile(r)

	tok, status, err := s.generateResourceToken(r.Context(), clientID, name, viewName, grantRole, ttl, keyFile, id, cfg, res, view)
	if err != nil {
		common.HandleError(status, err, w)
		return
	}

	if keyFile {
		common.SendJSONResponse(tok.Token, w)
		return
	}
	resp := &pb.GetTokenResponse{
		Name:    tok.Name,
		View:    tok.View,
		Account: tok.Account,
		Token:   tok.Token,
		Ttl:     tok.Ttl,
	}
	common.SendResponse(resp, w)
}

func (s *Service) damIssuerString() string {
	return s.domainURL + oidcPrefix
}

func (s *Service) generateResourceToken(ctx context.Context, clientID, resourceName, viewName, role string, ttl time.Duration, useKeyFile bool, id *ga4gh.Identity, cfg *pb.DamConfig, res *pb.Resource, view *pb.View) (*pb.ResourceToken, int, error) {
	sRole, err := adapter.ResolveServiceRole(role, view, res, cfg)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	if !viewHasRole(view, role) {
		return nil, http.StatusBadRequest, fmt.Errorf("role %q is not defined on resource %q view %q", role, resourceName, viewName)
	}
	st, ok := cfg.ServiceTemplates[view.ServiceTemplate]
	if !ok {
		return nil, http.StatusInternalServerError, fmt.Errorf("view %q service template %q is not defined", viewName, view.ServiceTemplate)
	}
	adapt := s.adapters.ByName[st.TargetAdapter]
	var aggregates []*adapter.AggregateView
	if adapt.IsAggregator() {
		aggregates, err = s.resolveAggregates(res, view, cfg)
		if err != nil {
			return nil, http.StatusInternalServerError, err
		}
	}
	tokenFormat := ""
	if useKeyFile {
		tokenFormat = "application/json"
	}
	adapterAction := &adapter.Action{
		Aggregates:      aggregates,
		Identity:        id,
		Issuer:          s.damIssuerString(),
		ClientID:        clientID,
		Config:          cfg,
		GrantRole:       role,
		MaxTTL:          maxTTL,
		Resource:        res,
		ServiceRole:     sRole,
		ServiceTemplate: st,
		TTL:             ttl,
		View:            view,
		TokenFormat:     tokenFormat,
	}
	result, err := adapt.MintToken(ctx, adapterAction)
	if err != nil {
		return nil, http.StatusServiceUnavailable, err
	}

	if !useKeyFile {
		return &pb.ResourceToken{
			Name:    resourceName,
			View:    s.makeView(viewName, view, res, cfg),
			Account: result.Account,
			Token:   result.Token,
			Ttl:     common.TtlString(ttl),
		}, http.StatusOK, nil
	}

	if common.IsJSON(result.TokenFormat) {
		return &pb.ResourceToken{Token: result.Token}, http.StatusOK, nil
	}
	return nil, http.StatusBadRequest, fmt.Errorf("adapter cannot create key file format")
}

func sendRedirect(url string, r *http.Request, w http.ResponseWriter) {
	common.AddCorsHeaders(w)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (s *Service) oauthConf(brokerName string, broker *pb.TrustedPassportIssuer, clientSecret string, scopes []string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     broker.ClientId,
		ClientSecret: clientSecret,
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  broker.AuthUrl,
			TokenURL: broker.TokenUrl,
		},
		RedirectURL: s.domainURL + loggedInPath,
	}
}

type resourceViewRole struct {
	resource string
	view     string
	role     string
}

func (s *Service) resourceViewRoleFromRequest(r *http.Request) (*resourceViewRole, error) {
	res := common.GetParam(r, "resource")
	if len(res) == 0 {
		return nil, fmt.Errorf("resource parameter not found")
	}

	fmt.Println(s.domainURL)
	if !strings.HasPrefix(res, s.domainURL) {
		return nil, fmt.Errorf("requested resouce not in this DAM")
	}
	path := strings.ReplaceAll(res, s.domainURL+basePath+"/", "")

	m := viewPathRE.FindStringSubmatch(path)
	if len(m) > 0 {
		return &resourceViewRole{resource: m[1], view: m[2]}, nil
	}
	m = rolePathRE.FindStringSubmatch(path)
	if len(m) > 0 {
		return &resourceViewRole{resource: m[1], view: m[2], role: m[3]}, nil
	}
	return nil, fmt.Errorf("resource parameter with invalid format")
}

type resourceAuthHandlerIn struct {
	realm           string
	stateID         string
	redirect        string
	ttl             time.Duration
	resource        string
	view            string
	role            string
	clientID        string
	responseKeyFile bool
}

type resourceAuthHandlerOut struct {
	oauth   *oauth2.Config
	stateID string
}

func (s *Service) resourceAuth(ctx context.Context, in resourceAuthHandlerIn) (*resourceAuthHandlerOut, int, error) {
	tx, err := s.store.Tx(true)
	if err != nil {
		return nil, http.StatusServiceUnavailable, err
	}
	defer tx.Finish()

	cfg, err := s.loadConfig(tx, in.realm)
	if err != nil {
		return nil, http.StatusServiceUnavailable, err
	}

	sec, err := s.loadSecrets(tx)
	if err != nil {
		return nil, http.StatusServiceUnavailable, err
	}

	for name, client := range cfg.Clients {
		if client.ClientId != in.clientID {
			continue
		}
		urlAllow := false
		for _, uri := range client.RedirectUris {
			if uri == in.redirect {
				urlAllow = true
				break
			}
		}
		if !urlAllow {
			return nil, http.StatusBadRequest, fmt.Errorf("redirect url %q is not allow for client %q", in.redirect, name)
		}
	}

	resName := in.resource
	viewName := in.view
	roleName := in.role
	if err := checkName(resName); err != nil {
		return nil, http.StatusBadRequest, err
	}
	if err := checkName(viewName); err != nil {
		return nil, http.StatusBadRequest, err
	}

	res, ok := cfg.Resources[resName]
	if !ok {
		return nil, http.StatusNotFound, fmt.Errorf("resource not found: %q", resName)
	}
	view, ok := res.Views[viewName]
	if !ok {
		return nil, http.StatusNotFound, fmt.Errorf("view %q not found for resource %q", viewName, resName)
	}
	grantRole := roleName
	if len(grantRole) == 0 {
		grantRole = view.DefaultRole
	}
	if !viewHasRole(view, grantRole) {
		return nil, http.StatusBadRequest, fmt.Errorf("role %q is not defined on resource %q view %q", grantRole, resName, viewName)
	}
	// TODO: need support real policy filter
	scopes := []string{"openid", "ga4gh", "identities", "account_admin"}

	broker, ok := cfg.TrustedPassportIssuers[s.defaultBroker]
	if !ok {
		return nil, http.StatusBadRequest, fmt.Errorf("broker %q is not defined", s.defaultBroker)
	}
	clientSecret, ok := sec.GetBrokerSecrets()[broker.ClientId]
	if !ok {
		return nil, http.StatusBadRequest, fmt.Errorf("client secret of broker %q is not defined", s.defaultBroker)
	}

	sID := uuid.New()

	state := &pb.ResourceTokenRequestState{
		Realm:           in.realm,
		ClientId:        in.clientID,
		Resource:        resName,
		View:            viewName,
		Role:            grantRole,
		State:           in.stateID,
		Broker:          s.defaultBroker,
		Redirect:        in.redirect,
		Ttl:             int64(in.ttl),
		ResponseKeyFile: in.responseKeyFile,
	}

	err = s.store.WriteTx(storage.ResourceTokenRequestStateDataType, storage.DefaultRealm, storage.DefaultUser, sID, storage.LatestRev, state, nil, tx)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}

	conf := s.oauthConf(s.defaultBroker, broker, clientSecret, scopes)
	return &resourceAuthHandlerOut{
		oauth:   conf,
		stateID: sID,
	}, http.StatusOK, nil
}

// ResourceAuthHandler implements OAuth2 endpoint "/authorize" for resource authorize.
// custom params:
// - realm: optional, if not present, use default realm
// - resource: format: DAM_URL/dam/resources/{resourceName}/views/{viewName}[/roles/{roleName}]
//             TODO: support multi resource in 1 request
// - ttl: request ttl for resource token
//        TODO: should use max_age instead of ttl
func (s *Service) ResourceAuthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request method %s not allowed", r.Method), w)
		return
	}

	stateID := common.GetParam(r, "state")
	if len(stateID) == 0 {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request must include state"), w)
	}

	redirectURL := common.GetParam(r, "redirect_uri")
	if len(redirectURL) == 0 {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request must include redirect"), w)
		return
	}

	ttl, err := extractTTL(r)
	if err != nil {
		common.HandleError(http.StatusBadRequest, err, w)
		return
	}

	rvr, err := s.resourceViewRoleFromRequest(r)
	if err != nil {
		common.HandleError(http.StatusBadRequest, err, w)
		return
	}

	in := resourceAuthHandlerIn{
		realm:           common.GetParamOrDefault(r, "realm", storage.DefaultRealm),
		stateID:         stateID,
		redirect:        redirectURL,
		ttl:             ttl,
		resource:        rvr.resource,
		view:            rvr.view,
		role:            rvr.role,
		clientID:        getClientID(r),
		responseKeyFile: responseKeyFile(r),
	}

	out, status, err := s.resourceAuth(r.Context(), in)
	if err != nil {
		common.HandleError(status, err, w)
		return
	}

	u := out.oauth.AuthCodeURL(out.stateID)

	sendRedirect(u, r, w)
}

type loggedInHandlerIn struct {
	authCode string
	stateID  string
}

type loggedInHandlerOut struct {
	redirect string
	authCode string
	stateID  string
}

func (s *Service) loggedIn(ctx context.Context, in loggedInHandlerIn) (*loggedInHandlerOut, int, error) {
	tx, err := s.store.Tx(true)
	if err != nil {
		return nil, http.StatusServiceUnavailable, err
	}
	defer tx.Finish()

	state := &pb.ResourceTokenRequestState{}
	err = s.store.ReadTx(storage.ResourceTokenRequestStateDataType, storage.DefaultRealm, storage.DefaultUser, in.stateID, storage.LatestRev, state, tx)
	if err != nil {
		return nil, http.StatusServiceUnavailable, err
	}

	cfg, err := s.loadConfig(tx, state.Realm)
	if err != nil {
		return nil, http.StatusServiceUnavailable, err
	}

	sec, err := s.loadSecrets(tx)
	if err != nil {
		return nil, http.StatusServiceUnavailable, err
	}

	broker, ok := cfg.TrustedPassportIssuers[state.Broker]
	if !ok {
		return nil, http.StatusBadRequest, fmt.Errorf("unknown identity broker %q", state.Broker)
	}

	clientSecret, ok := sec.GetBrokerSecrets()[broker.ClientId]
	if !ok {
		return nil, http.StatusBadRequest, fmt.Errorf("client secret of broker %q is not defined", s.defaultBroker)
	}

	// Use code exchange tokens.
	conf := s.oauthConf(state.Broker, broker, clientSecret, []string{})
	tok, err := conf.Exchange(ctx, in.authCode)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("token exchange failed. %s", err)
	}

	id, err := s.tokenToPassportIdentity(cfg, tx, tok.AccessToken, broker.ClientId)
	if err != nil {
		return nil, http.StatusUnauthorized, err
	}

	ttl := time.Duration(state.Ttl)

	res, ok := cfg.Resources[state.Resource]
	if !ok {
		return nil, http.StatusNotFound, fmt.Errorf("resource not found: %q", state.Resource)
	}

	view, ok := res.Views[state.View]
	if !ok {
		return nil, http.StatusNotFound, fmt.Errorf("view %q not found for resource %q", state.View, state.Resource)
	}

	status, err := s.checkAuthorization(id, ttl, state.Resource, state.View, state.Role, cfg, state.ClientId, nil)
	if err != nil {
		return nil, status, err
	}

	keyFile := state.ResponseKeyFile
	sTok, status, err := s.generateResourceToken(ctx, state.ClientId, state.Resource, state.View, state.Role, ttl, keyFile, id, cfg, res, view)
	if err != nil {
		return nil, status, err
	}

	respAuthCode := uuid.New()
	authCode := &pb.AuthCode{
		ClientId:        state.ClientId,
		ResponseKeyFile: keyFile,
		Tokens: map[string]*pb.ResourceToken{
			// TODO: should support multi resource tokens.
			"token": sTok,
		},
	}
	err = s.store.WriteTx(storage.AuthCodeDatatype, storage.DefaultRealm, storage.DefaultUser, respAuthCode, storage.LatestRev, authCode, nil, tx)
	if err != nil {
		return nil, http.StatusServiceUnavailable, err
	}

	return &loggedInHandlerOut{
		redirect: state.Redirect,
		authCode: respAuthCode,
		stateID:  state.State,
	}, http.StatusOK, nil
}

// LoggedInHandler implements endpoint "/loggedin" for broker auth code redirect.
func (s *Service) LoggedInHandler(w http.ResponseWriter, r *http.Request) {
	code, err := extractAuthCode(r)
	if err != nil {
		common.HandleError(http.StatusBadRequest, err, w)
		return
	}

	stateID := common.GetParam(r, "state")
	if len(stateID) == 0 {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request must include state"), w)
	}

	out, status, err := s.loggedIn(r.Context(), loggedInHandlerIn{authCode: code, stateID: stateID})
	if err != nil {
		common.HandleError(status, err, w)
		return
	}

	u, err := url.Parse(out.redirect)
	if err != nil {
		common.HandleError(http.StatusInternalServerError, fmt.Errorf("url.Parse(%q) failed, %s", out.redirect, err), w)
		return
	}

	q := u.Query()
	q.Add("code", out.authCode)
	q.Add("state", out.stateID)
	u.RawQuery = q.Encode()

	sendRedirect(u.String(), r, w)
}

type exchangeResourceTokenHandlerIn struct {
	authCode string
	clientID string
}

type exchangeResourceTokenHandlerOut struct {
	responseKeyFile bool
	tokens          map[string]*pb.ResourceToken
}

func (s *Service) exchangeResourceToken(ctx context.Context, in exchangeResourceTokenHandlerIn) (*exchangeResourceTokenHandlerOut, int, error) {
	tx, err := s.store.Tx(true)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	defer tx.Finish()

	authCode := &pb.AuthCode{}
	err = s.store.ReadTx(storage.AuthCodeDatatype, storage.DefaultRealm, storage.DefaultUser, in.authCode, storage.LatestRev, authCode, tx)
	if err != nil {
		if storage.ErrNotFound(err) {
			return nil, http.StatusUnauthorized, fmt.Errorf("auth code invalid or has already been exchanged")
		}
		return nil, http.StatusServiceUnavailable, fmt.Errorf("reading auth code metadata from storage: %v", err)
	}

	if authCode.ClientId != in.clientID {
		// TODO: auth_code used with invalid client, consider auto revoke and audit the client.
		return nil, http.StatusBadRequest, fmt.Errorf("token exchange with wrong client id, wants %q, got %q", authCode.ClientId, in.clientID)
	}

	// auth code is one time usage.
	err = s.store.DeleteTx(storage.AuthCodeDatatype, storage.DefaultRealm, storage.DefaultUser, in.authCode, storage.LatestRev, tx)
	if err != nil {
		return nil, http.StatusServiceUnavailable, err
	}

	return &exchangeResourceTokenHandlerOut{
		responseKeyFile: authCode.ResponseKeyFile,
		tokens:          authCode.Tokens,
	}, http.StatusOK, nil
}

// ExchangeResourceTokenHandler implements oauth2 auth code token exchange.
func (s *Service) ExchangeResourceTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request method %s not allowed", r.Method), w)
		return
	}

	code, err := extractAuthCode(r)
	if err != nil {
		common.HandleError(http.StatusBadRequest, err, w)
		return
	}

	in := exchangeResourceTokenHandlerIn{
		authCode: code,
		clientID: getClientID(r),
	}

	out, status, err := s.exchangeResourceToken(r.Context(), in)
	if err != nil {
		common.HandleError(status, err, w)
		return
	}

	tok, ok := out.tokens["token"]
	if !ok {
		common.HandleError(http.StatusInternalServerError, fmt.Errorf("token not found in database AutCode object"), w)
		return
	}

	if out.responseKeyFile {
		common.SendJSONResponse(tok.Token, w)
		return
	}

	common.SendResponse(&pb.GetTokenResponse{
		Name:    tok.Name,
		View:    tok.View,
		Account: tok.Account,
		Token:   tok.Token,
		Ttl:     tok.Ttl,
	}, w)
}
