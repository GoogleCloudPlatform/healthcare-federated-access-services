// Copyright 2020 Google LLC
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

// Package hydraproxy contains a hydra proxy service to proxy request to hydra if needed.
package hydraproxy

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/hydra" /* copybara-comment: hydra */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	tpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/store/tokens" /* copybara-comment: go_proto */
)

// Service is the service proxy the request to hydra.
type Service struct {
	httpClient          *http.Client
	hydraAdminURL       string
	hydraPublicURLProxy *httputil.ReverseProxy
	store               storage.Store
}

// New creates the hydra proxy service.
func New(client *http.Client, hydraAdminURL, hydraPublicURLInternal string, store storage.Store) (*Service, error) {
	s := &Service{
		httpClient:    client,
		hydraAdminURL: hydraAdminURL,
		store:         store,
	}

	u, err := url.Parse(hydraPublicURLInternal)
	if err != nil {
		return nil, fmt.Errorf("url.Parse(%s): %v", hydraPublicURLInternal, err)
	}

	s.hydraPublicURLProxy = httputil.NewSingleHostReverseProxy(u)

	return s, nil
}

// HydraOAuthToken proxy the POST /oauth2/token request.
// - for code exhange token: do nothing, just proxy.
// - for refresh token exchange token: check the token is not revoked before proxy the request.
// TODO: should unify with HydraOAuthToken in DAM.
func (s *Service) HydraOAuthToken(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	// introspect the refresh token before proxy the request to exchange.
	if isRefreshTokenExchange(r) {
		deleted, err := s.tokenDeleted(r.PostFormValue("refresh_token"))
		if err != nil {
			httputils.WriteError(w, err)
			return
		}
		if deleted {
			httputils.WriteError(w, status.Errorf(codes.Unauthenticated, "token revoked"))
			return
		}
	}

	// Encode the form back into request body
	r.Body = ioutil.NopCloser(bytes.NewBufferString(r.PostForm.Encode()))

	s.hydraPublicURLProxy.ServeHTTP(w, r)
}

func isRefreshTokenExchange(r *http.Request) bool {
	return r.PostFormValue("grant_type") == "refresh_token"
}

// tokenRevoked checks if token is in pending delete state, if it is in pending delete state, revoke it from hydra.
// Returns deleted and error
func (s *Service) tokenDeleted(refreshToken string) (_ bool, ferr error) {
	if len(refreshToken) == 0 {
		return false, status.Error(codes.FailedPrecondition, "no refresh_token")
	}

	in, err := hydra.Introspect(s.httpClient, s.hydraAdminURL, refreshToken)
	if err != nil {
		return false, err
	}

	tid, err := hydra.ExtractTokenIDInIntrospect(in)
	if err != nil {
		return false, err
	}

	tx, err := s.store.Tx(true)
	if err != nil {
		return false, status.Errorf(codes.Unavailable, "tokenDeleted: can not get tx: %v", err)
	}
	defer func() {
		err := tx.Finish()
		if ferr == nil {
			ferr = err
		}
	}()

	pending := &tpb.PendingDeleteToken{}
	err = s.store.ReadTx(storage.PendingDeleteTokenDatatype, storage.DefaultRealm, in.Subject, tid, storage.LatestRev, pending, tx)
	if err != nil {
		// No pending delete for this token.
		if storage.ErrNotFound(err) {
			return false, nil
		}
		return false, status.Errorf(codes.Unavailable, "tokenDeleted: read PendingDeleteToken failed: %v", err)
	}

	// delete this token
	if err := hydra.RevokeToken(s.httpClient, s.hydraAdminURL, refreshToken); err != nil {
		return false, err
	}

	if err := s.store.DeleteTx(storage.PendingDeleteTokenDatatype, storage.DefaultRealm, in.Subject, tid, storage.LatestRev, tx); err != nil {
		return false, status.Errorf(codes.Unavailable, "tokenDeleted: delete PendingDeleteToken failed: %v", err)
	}

	return true, err
}
