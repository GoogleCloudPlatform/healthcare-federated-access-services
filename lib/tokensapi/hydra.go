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

package tokensapi

import (
	"context"
	"strings"
	"time"

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"bitbucket.org/creachadair/stringset" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/hydra" /* copybara-comment: hydra */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	topb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/store/tokens" /* copybara-comment: go_proto */
)

// Hydra tokens management, implments TokenProvider interface.
type Hydra struct {
	hydraAdminURL string
	issuer        string
	clients       func(tx storage.Tx) (map[string]*cpb.Client, error)
}

// NewHydraTokenManager creates a Hydra token manger.
func NewHydraTokenManager(hydraAdminURL, issuer string, clients func(tx storage.Tx) (map[string]*cpb.Client, error)) *Hydra {
	return &Hydra{
		hydraAdminURL: hydraAdminURL,
		issuer:        issuer,
		clients:       clients,
	}
}

// ListTokens lists the tokens.
func (s *Hydra) ListTokens(ctx context.Context, user string, store storage.Store, tx storage.Tx) ([]*Token, error) {
	pendings, err := findUserPendingDeleteTokens(user, store, tx)
	if err != nil {
		return nil, err
	}

	sessions, err := hydra.ListConsents(httpClient, s.hydraAdminURL, user)
	if err != nil {
		return nil, err
	}
	clients, err := s.clients(tx)
	if err != nil {
		return nil, err
	}

	var tokens []*Token
	for _, se := range sessions {
		tid, err := hydra.ExtractTokenIDInConsentSession(se)
		// legacy token does not have a "tid", but it would not able to use anymore since it it not refresh able.
		if err != nil {
			continue
		}

		// token is already in pending delete state can not use anymore.
		if pendings.Contains(tid) {
			continue
		}

		t := &Token{
			User:        user,
			RawTokenID:  tid,
			TokenPrefix: s.TokenPrefix(),
			IssuedAt:    time.Time(se.HandledAt).Unix(),
			Platform:    s.TokenPrefix(),
			Issuer:      s.issuer,
			Subject:     se.ConsentRequest.Subject,
			Audience:    strings.Join(se.GrantedAudience, ","),
			Scope:       strings.Join(se.GrantedScope, " "),
		}

		if client, ok := clients[se.ConsentRequest.Client.Name]; ok {
			t.ClientID = client.ClientId
			t.ClientName = se.ConsentRequest.Client.Name
			t.ClientUI = client.Ui
		}

		tokens = append(tokens, t)
	}
	return tokens, nil
}

func findUserPendingDeleteTokens(user string, store storage.Store, tx storage.Tx) (stringset.Set, error) {
	res := stringset.Set{}

	pending := &topb.PendingDeleteToken{}
	offset := 0

	for {
		// maybe improve this with better query support like `id in [...]`.
		pendings, err := store.MultiReadTx(storage.PendingDeleteTokenDatatype, storage.DefaultRealm, user, storage.MatchAllIDs, nil, offset, storage.MaxPageSize, pending, tx)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "find pending delete token MultiReadTx() failed: %v", err)
		}
		for _, entry := range pendings.Entries {
			res.Add(entry.ItemID)
			offset++
		}

		// no more page
		if pendings.MatchCount < storage.MaxPageSize {
			break
		}
	}

	return res, nil
}

// DeleteToken revokes a token.
func (s *Hydra) DeleteToken(ctx context.Context, user, tokenID string, store storage.Store, tx storage.Tx) error {
	pending := &topb.PendingDeleteToken{}
	if err := store.WriteTx(storage.PendingDeleteTokenDatatype, storage.DefaultRealm, user, tokenID, storage.LatestRev, pending, nil, tx); err != nil {
		return status.Errorf(codes.Unavailable, "write PendingDeleteToken token failed: %v", err)
	}
	return nil
}

// TokenPrefix of Hydra provided tokens.
func (s *Hydra) TokenPrefix() string {
	return "hydra"
}
