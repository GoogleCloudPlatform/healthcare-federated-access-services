// Copyright 2020 Google LLC.
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

// Package cli adds support for command line interfaces or micro-services
// to establish an access and/or refresh token via user participation.
package cli

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/mail"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/gorilla/mux" /* copybara-comment */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
	"github.com/golang/protobuf/ptypes" /* copybara-comment */
	"github.com/pborman/uuid" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/auth" /* copybara-comment: auth */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/handlerfactory" /* copybara-comment: handlerfactory */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/kms" /* copybara-comment: kms */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/srcutil" /* copybara-comment: srcutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/translator" /* copybara-comment: translator */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
)

const (
	cliPageFile = "pages/cli.html"
	staticPath  = "/static"
)

var (
	ttl          = 5 * time.Minute
	autoGenerate = "auto"
)

// RegisterFactory creates handlers for shell login requests.
func RegisterFactory(store storage.Store, path string, crypt kms.Encryption, cliAuthURL, issuerURL, authURL, tokenURL, accept string, httpClient *http.Client) *handlerfactory.Options {
	return &handlerfactory.Options{
		TypeName:            "registerLogin",
		PathPrefix:          path,
		HasNamedIdentifiers: true,
		NameChecker: map[string]*regexp.Regexp{
			"name": regexp.MustCompile(`^(auto|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$`),
		},
		Service: NewRegisterHandler(store, crypt, cliAuthURL, issuerURL, authURL, tokenURL, accept, httpClient),
	}
}

// RegisterHandler handles shell login requests.
type RegisterHandler struct {
	store      storage.Store
	crypt      kms.Encryption
	cliAuthURL string
	issuerURL  string
	authURL    string
	tokenURL   string
	accept     string
	item       *cpb.CliState
	save       *cpb.CliState
	client     *http.Client
	tx         storage.Tx
}

// NewRegisterHandler handles one shell login request.
func NewRegisterHandler(store storage.Store, crypt kms.Encryption, cliAuthURL, issuerURL, authURL, tokenURL, accept string, httpClient *http.Client) *RegisterHandler {
	return &RegisterHandler{
		store:      store,
		crypt:      crypt,
		cliAuthURL: cliAuthURL,
		issuerURL:  issuerURL,
		authURL:    authURL,
		tokenURL:   tokenURL,
		accept:     accept,
		item:       &cpb.CliState{},
		client:     httpClient,
	}
}

// Setup sets up the handler.
func (h *RegisterHandler) Setup(r *http.Request, tx storage.Tx) (int, error) {
	h.item.Reset()
	h.tx = tx
	return http.StatusOK, nil
}

// LookupItem looks up the item in the storage layer.
func (h *RegisterHandler) LookupItem(r *http.Request, name string, vars map[string]string) bool {
	if name == autoGenerate {
		return false
	}
	if err := h.store.ReadTx(storage.CliAuthDatatype, getRealm(r), storage.DefaultUser, name, storage.LatestRev, h.item, h.tx); err != nil {
		return false
	}
	return true
}

// NormalizeInput sets up basic structure of request input objects if absent.
func (h *RegisterHandler) NormalizeInput(r *http.Request, name string, vars map[string]string) error {
	return nil
}

// Get is a GET request.
func (h *RegisterHandler) Get(r *http.Request, name string) (proto.Message, error) {
	a, err := auth.FromContext(r.Context())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "cannot obtain request context: %v", err)
	}
	if h.item.State != storage.StateActive {
		return nil, status.Errorf(codes.FailedPrecondition, "login %q has already been granted to a user on a previous call", name)
	}
	exp, err := ptypes.Timestamp(h.item.ExpiresAt)
	if err != nil {
		exp = time.Unix(0, 0)
	}

	if time.Now().Sub(exp) > 0 {
		return nil, status.Errorf(codes.DeadlineExceeded, "login %q expired", name)
	}
	if a.ClientID != h.item.ClientId {
		return nil, status.Errorf(codes.Unauthenticated, "login %q unauthorized client", name)
	}
	secret := httputils.QueryParam(r, "login_secret")
	if secret == "" {
		return nil, status.Errorf(codes.InvalidArgument, "missing login_secret")
	}
	if len(h.item.EncryptedSecret) == 0 {
		return nil, status.Errorf(codes.Internal, "missing internal secret")
	}
	decrypted, err := h.crypt.Decrypt(r.Context(), h.item.EncryptedSecret, "")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "decrypt secret failed: %v", err)
	}
	if secret != string(decrypted) {
		if err := h.store.DeleteTx(storage.CliAuthDatatype, getRealm(r), storage.DefaultUser, name, storage.LatestRev, h.tx); err != nil {
			return nil, status.Errorf(codes.Internal, "failed to remove registration")
		}
		return nil, status.Errorf(codes.Unauthenticated, "unauthorized: missing or invalid login_secret")
	}
	if len(h.item.EncryptedCode) > 0 {
		if err = h.exchangeCode(r, name, a); err != nil {
			return nil, err
		}
	}
	h.item.EncryptedSecret = nil
	h.item.State = ""
	return h.item, nil
}

func (h *RegisterHandler) exchangeCode(r *http.Request, name string, a *auth.Context) error {
	// Can only use code once. Exchange code now and mark CliState as DELETED in storage.
	// Future calls to GET can give more meaningful error messages to the end user.
	if err := h.tx.MakeUpdate(); err != nil {
		return status.Errorf(codes.Internal, "storage transaction prepare update failed: %v", err)
	}
	encrypted := h.item.EncryptedCode
	h.item.EncryptedCode = nil
	h.item.AuthUrl = ""
	h.item.State = storage.StateDeleted
	if err := h.store.WriteTx(storage.CliAuthDatatype, getRealm(r), storage.DefaultUser, name, storage.LatestRev, h.item, nil, h.tx); err != nil {
		return status.Errorf(codes.Internal, "failed to remove registration")
	}
	decrypted, err := h.crypt.Decrypt(r.Context(), encrypted, "")
	if err != nil {
		return status.Errorf(codes.Internal, "decrypt code failed: %v", err)
	}
	code := string(decrypted)
	q := fmt.Sprintf("grant_type=authorization_code&redirect_uri=%s&code=%s", url.QueryEscape(h.accept), url.QueryEscape(code))
	authZ := "Basic " + base64.StdEncoding.EncodeToString([]byte(a.ClientID+":"+a.ClientSecret))
	tokens := &cpb.OidcTokenResponse{}

	if err = h.oidcFetch(http.MethodPost, h.tokenURL, q, authZ, "fetch tokens", tokens); err != nil {
		return err
	}

	id := &ga4gh.Identity{Issuer: h.issuerURL}
	info, err := translator.FetchUserinfoClaims(r.Context(), h.client, id, tokens.AccessToken, nil)
	if err != nil {
		return status.Errorf(codes.Unavailable, "fetch user info claims failed: %v", err)
	}
	if info.Email == "" {
		return status.Errorf(codes.Unauthenticated, "user email claim not provided, cannot verify email match")
	}
	if info.Email != h.item.Email {
		return status.Errorf(codes.Unauthenticated, "unexpected user: registered for user %q, got user %q", h.item.Email, id.Email)
	}

	h.item.AccessToken = tokens.AccessToken
	h.item.RefreshToken = tokens.RefreshToken
	h.item.UserProfile = map[string]string{
		"email":       info.Email,
		"family_name": info.FamilyName,
		"given_name":  info.GivenName,
		"name":        info.Name,
		"nickname":    info.Nickname,
		"subject":     info.Subject,
	}
	return nil
}

func (h *RegisterHandler) oidcFetch(method, url, input, authZ, label string, msg proto.Message) error {
	req, err := http.NewRequest(method, url, strings.NewReader(input))
	if err != nil {
		return status.Errorf(codes.Internal, "%s prepare RPC failed: %v", label, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", authZ)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := h.client.Do(req)
	if err != nil {
		return status.Errorf(codes.Unavailable, "%s failed: %v", label, err)
	}
	if !httputils.IsHTTPSuccess(resp.StatusCode) {
		body, _ := ioutil.ReadAll(resp.Body)
		str := string(body)
		if str == "" {
			str = "<empty response>"
		}
		return status.Errorf(codes.Unavailable, "%s failed (status code %d): %v", label, resp.StatusCode, str)
	}
	defer resp.Body.Close()
	if err = httputils.DecodeJSON(resp.Body, msg); err != nil {
		return status.Errorf(codes.Unavailable, "%s decode response failed: %v", label, err)
	}
	return nil
}

// Post is a POST request.
func (h *RegisterHandler) Post(r *http.Request, name string) (proto.Message, error) {
	if name == autoGenerate {
		name = uuid.New()
	}
	email := httputils.QueryParam(r, "email")
	if len(email) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "missing email address parameter")
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid email address %q: %v", email, err)
	}
	scope := httputils.QueryParamWithDefault(r, "scope", "openid profile email offline")
	cat := time.Now()
	exp := cat.Add(ttl)
	catProto, err := ptypes.TimestampProto(cat)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "cannot generate iat timestamp: %v", err)
	}
	expProto, err := ptypes.TimestampProto(exp)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "cannot generate exp timestamp: %v", err)
	}
	secret := uuid.New()
	encrypted, err := h.crypt.Encrypt(r.Context(), []byte(secret), "")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "cannot generate secret: %v", err)
	}
	a, err := auth.FromContext(r.Context())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "cannot obtain request context: %v", err)
	}
	u, err := url.Parse(h.authURL)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "invalid redirect URL: %v", err)
	}
	q := u.Query()
	q.Set("grant_type", "authorization_code")
	q.Set("response_type", "code")
	q.Set("client_id", a.ClientID)
	q.Set("scope", scope)
	q.Set("state", name)
	q.Set("redirect_uri", h.accept)
	u.RawQuery = q.Encode()
	h.save = &cpb.CliState{
		Id:              name,
		Email:           email,
		EncryptedSecret: encrypted,
		ClientId:        a.ClientID,
		Scope:           scope,
		AuthUrl:         u.String(),
		CreatedAt:       catProto,
		ExpiresAt:       expProto,
		State:           storage.StateActive,
	}

	// Return the non-encrypted secret whereas `h.save` above will have the secret encrypted.
	return &cpb.CliState{
		Id:        h.save.Id,
		Email:     h.save.Email,
		Secret:    secret,
		Scope:     scope,
		AuthUrl:   strings.Replace(h.cliAuthURL, "{name}", name, -1),
		CreatedAt: catProto,
		ExpiresAt: expProto,
	}, nil
}

// Put is a PUT request.
func (h *RegisterHandler) Put(r *http.Request, name string) (proto.Message, error) {
	return nil, status.Errorf(codes.InvalidArgument, "PUT not allowed")
}

// Patch is a PATCH request.
func (h *RegisterHandler) Patch(r *http.Request, name string) (proto.Message, error) {
	return nil, status.Errorf(codes.InvalidArgument, "PATCH not allowed")
}

// Remove is a DELETE request.
func (h *RegisterHandler) Remove(r *http.Request, name string) (proto.Message, error) {
	return nil, h.store.DeleteTx(storage.CliAuthDatatype, getRealm(r), storage.DefaultUser, name, storage.LatestRev, h.tx)
}

// CheckIntegrity checks that any modifications make sense before applying them.
func (h *RegisterHandler) CheckIntegrity(*http.Request) *status.Status {
	return nil
}

// Save will save any modifications done for the request.
func (h *RegisterHandler) Save(r *http.Request, tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	if h.save == nil {
		return nil
	}
	id := h.save.Id // don't use "name" to handle autoGenerate case
	return h.store.WriteTx(storage.CliAuthDatatype, getRealm(r), storage.DefaultUser, id, storage.LatestRev, h.save, nil, h.tx)
}

////////////////////////////////////////////////////////////

// AuthHandler handles one CLI auth request.
type AuthHandler struct {
	auth   string
	accept string
	store  storage.Store
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(store storage.Store) *AuthHandler {
	return &AuthHandler{
		store: store,
	}
}

// Handle handles a CLI authentication request.
func (h *AuthHandler) Handle(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
	item := &cpb.CliState{}
	if err := h.store.ReadTx(storage.CliAuthDatatype, getRealm(r), storage.DefaultUser, name, storage.LatestRev, item, nil); err != nil {
		if storage.ErrNotFound(err) {
			httputils.WriteError(w, status.Errorf(codes.NotFound, "login %q not found", name))
			return
		}
		httputils.WriteError(w, status.Errorf(codes.Unavailable, "load login %q failed: storage is unavailable", name))
		return
	}
	httputils.WriteRedirect(w, r, item.AuthUrl)
}

////////////////////////////////////////////////////////////

// AcceptHandler handles one CLI auth request.
type AcceptHandler struct {
	store storage.Store
	crypt kms.Encryption
	page  string
}

// NewAcceptHandler creates a new AcceptHandler.
func NewAcceptHandler(store storage.Store, crypt kms.Encryption, rootPath string) *AcceptHandler {
	page, err := srcutil.LoadFile(cliPageFile)
	if err != nil {
		page = "<html><body>CLI Login: did not load page correctly.</body></html>"
	}
	assetPath := path.Join(rootPath, staticPath)
	page = strings.Replace(page, "${ASSET_DIR}", assetPath, -1)

	return &AcceptHandler{
		store: store,
		crypt: crypt,
		page:  page,
	}
}

// Handle handles an accept redirect request.
func (h *AcceptHandler) Handle(w http.ResponseWriter, r *http.Request) {
	name := httputils.QueryParam(r, "state")
	if name == "" {
		// Error state, provide page content to display error (hash messages on page can override).
		writeAcceptPage(w, h.page, status.Errorf(codes.InvalidArgument, "missing state parameter"))
		return
	}
	if name == "" {
		writeAcceptPage(w, h.page, status.Errorf(codes.InvalidArgument, "login failed: missing state query parameter"))
		return
	}
	item := &cpb.CliState{}
	if err := h.store.ReadTx(storage.CliAuthDatatype, getRealm(r), storage.DefaultUser, name, storage.LatestRev, item, nil); err != nil {
		if storage.ErrNotFound(err) {
			writeAcceptPage(w, h.page, status.Errorf(codes.NotFound, "login %q not found", name))
			return
		}
		writeAcceptPage(w, h.page, status.Errorf(codes.Unavailable, "load login %q failed: storage is unavailable", name))
		return
	}

	// Make sure the item can only be used once by checking if it was accepted previously.
	if item.AcceptedAt != nil || len(item.EncryptedCode) > 0 || item.State != storage.StateActive {
		if item.State == storage.StateActive {
			item.State = storage.StateDisabled
			h.store.WriteTx(storage.CliAuthDatatype, getRealm(r), storage.DefaultUser, name, storage.LatestRev, item, nil, nil)
		}
		writeAcceptPage(w, h.page, status.Errorf(codes.Unauthenticated, "login %q has already been accepted by another login flow", name))
		return
	}
	atProto, err := ptypes.TimestampProto(time.Now())
	if err != nil {
		writeAcceptPage(w, h.page, status.Errorf(codes.Internal, "login %q cannot generate timestamp: %v", name, err))
		return
	}
	item.AcceptedAt = atProto

	nonce := httputils.QueryParam(r, "nonce")
	if nonce != "" && nonce != item.Nonce {
		writeAcceptPage(w, h.page, status.Errorf(codes.InvalidArgument, "login failed: nonce mismatch"))
		return
	}
	exp, err := ptypes.Timestamp(item.ExpiresAt)
	if err != nil {
		exp = time.Unix(0, 0)
	}

	if time.Now().Sub(exp) > 0 {
		writeAcceptPage(w, h.page, status.Errorf(codes.DeadlineExceeded, "login %q failed: the login state has expired", name))
		return
	}
	code := httputils.QueryParam(r, "code")
	if len(code) == 0 {
		item.State = storage.StateDisabled
		h.store.WriteTx(storage.CliAuthDatatype, getRealm(r), storage.DefaultUser, name, storage.LatestRev, item, nil, nil)
		writeAcceptPage(w, h.page, status.Errorf(codes.InvalidArgument, "login %q failed: no auth code provided", name))
		return
	}
	cryptcode, err := h.crypt.Encrypt(r.Context(), []byte(code), "")
	if err != nil {
		writeAcceptPage(w, h.page, status.Errorf(codes.Internal, "cannot generate secret: %v", err))
	}
	item.EncryptedCode = cryptcode
	if err := h.store.WriteTx(storage.CliAuthDatatype, getRealm(r), storage.DefaultUser, name, storage.LatestRev, item, nil, nil); err != nil {
		writeAcceptPage(w, h.page, status.Errorf(codes.Unavailable, "write login %q failed: storage is unavailable", name))
		return
	}
	writeAcceptPage(w, h.page, nil)
}

////////////////////////////////////////////////////////////

func getRealm(r *http.Request) string {
	return storage.DefaultRealm
}

func writeAcceptPage(w http.ResponseWriter, page string, err error) {
	code := codes.OK
	e := ""
	desc := ""
	hint := ""
	if err != nil {
		code = httputils.RPCCode(httputils.FromError(err))
		parts := strings.SplitN(err.Error(), ":", 2)
		e = code.String()
		desc = parts[0]
		if len(parts) > 1 {
			hint = parts[1]
		}
	}
	page = strings.Replace(page, "${ERROR}", e, -1)
	page = strings.Replace(page, "${DESC}", desc, -1)
	page = strings.Replace(page, "${HINT}", hint, -1)
	httputils.WriteHTMLResp(w, page)
}
