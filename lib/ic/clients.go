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

package ic

import (
	"fmt"
	"net/http"

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/check" /* copybara-comment: check */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common" /* copybara-comment: common */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/handlerfactory" /* copybara-comment: handlerfactory */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/oathclients" /* copybara-comment: oathclients */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/ic/v1" /* copybara-comment: go_proto */
)

type clientService struct {
	s    *Service
	cfg  *pb.IcConfig
	sec  *pb.IcSecrets
	item *cpb.Client
	save bool
}

func (c *clientService) ClientByName(name string) *cpb.Client {
	return c.cfg.Clients[name]
}

func (c *clientService) HandlerSetup(tx storage.Tx, r *http.Request) (*ga4gh.Identity, int, error) {
	cfg, sec, id, status, err := c.s.handlerSetup(tx, r, noScope, nil)
	c.cfg = cfg
	c.sec = sec
	return id, status, err
}

func (c *clientService) SaveClient(name, secret string, cli *cpb.Client) {
	c.cfg.Clients[name] = cli
	c.sec.ClientSecrets[cli.ClientId] = secret
	c.save = true
}

func (c *clientService) RemoveClient(name string, cli *cpb.Client) {
	delete(c.cfg.Clients, name)
	delete(c.sec.ClientSecrets, cli.ClientId)
	c.save = true
}

func (c *clientService) Save(tx storage.Tx, desc, typeName string, r *http.Request, id *ga4gh.Identity, m *cpb.ConfigModification) error {
	if !c.save || (m != nil && m.DryRun) {
		return nil
	}

	if err := c.s.saveConfig(c.cfg, desc, typeName, r, id, c.item, c.item, toICModification(m), tx); err != nil {
		return err
	}
	if err := c.s.saveSecrets(c.sec, desc, typeName, r, id, tx); err != nil {
		return err
	}

	return nil
}

func (c *clientService) CheckIntegrity(r *http.Request, m *cpb.ConfigModification) *status.Status {
	if err := check.CheckReadOnly(getRealm(r), c.cfg.Options.ReadOnlyMasterRealm, c.cfg.Options.WhitelistedRealms); err != nil {
		return httputil.NewStatus(codes.InvalidArgument, err.Error())
	}
	if err := configRevision(toICModification(m), c.cfg); err != nil {
		return httputil.NewStatus(codes.InvalidArgument, err.Error())
	}
	if err := c.s.checkConfigIntegrity(c.cfg); err != nil {
		return httputil.NewStatus(codes.InvalidArgument, err.Error())
	}
	return nil
}

//////////////////////////////////////////////////////////////////
// GET /identity/v1alpha/{realm}/config/clients/{name}:
//   Return any given client information
//   Require admin token
//
// POST /identity/v1alpha/{realm}/config/clients/{name}:
//   Add given client in http body
//   Require admin token
//   Return added client information
//
// PATCH /identity/v1alpha/{realm}/config/clients/{name}:
//   Update given client
//   Require admin token
//   Return any client information
//
// DELETE /identity/v1alpha/{realm}/config/clients/{name}:
//   Delete given client
//   Require admin token
//   Return nothing
//////////////////////////////////////////////////////////////////

func (s *Service) configClientFactory() *handlerfactory.HandlerFactory {
	c := &clientService{s: s}

	return &handlerfactory.HandlerFactory{
		TypeName:            "configClient",
		PathPrefix:          configClientsPath,
		HasNamedIdentifiers: true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) handlerfactory.HandlerInterface {
			return oathclients.NewAdminClientHandler(w, r, c, c.s.useHydra, c.s.httpClient, c.s.hydraAdminURL)
		},
	}
}

func toICModification(m *cpb.ConfigModification) *pb.ConfigModification {
	if m == nil {
		return nil
	}
	return &pb.ConfigModification{
		Revision: m.Revision,
		DryRun:   m.DryRun,
	}
}

//////////////////////////////////////////////////////////////////
// GET /dam/v1alpha/{realm}/clients:sync:
//   Return empty response on success
//////////////////////////////////////////////////////////////////

func (s *Service) syncClientsFactory() *handlerfactory.HandlerFactory {
	return &handlerfactory.HandlerFactory{
		TypeName:            "configClientsSync",
		PathPrefix:          syncClientsPath,
		HasNamedIdentifiers: false,
		NewHandler: func(w http.ResponseWriter, r *http.Request) handlerfactory.HandlerInterface {
			return NewSyncClientsHandler(s, w, r)
		},
	}
}

type syncClientsHandler struct {
	s   *Service
	w   http.ResponseWriter
	r   *http.Request
	cfg *pb.IcConfig
	tx  storage.Tx
}

// NewSyncClientsHandler implements the sync Hydra clients RPC method.
func NewSyncClientsHandler(s *Service, w http.ResponseWriter, r *http.Request) *syncClientsHandler {
	return &syncClientsHandler{
		s: s,
		w: w,
		r: r,
	}
}
func (h *syncClientsHandler) Setup(tx storage.Tx) (int, error) {
	cfg, st, err := h.s.handlerSetupNoAuth(tx, h.r, nil)
	if err != nil {
		return st, err
	}

	cliID := getClientID(h.r)
	var scope string
	for _, c := range cfg.Clients {
		if c.ClientId == cliID {
			scope = c.Scope
			break
		}
	}

	if !common.ContainsWord(scope, "sync") {
		return http.StatusUnauthorized, status.Errorf(codes.PermissionDenied, `client does not have the 'sync' scope`)
	}

	h.cfg = cfg
	h.tx = tx
	return http.StatusOK, nil
}
func (h *syncClientsHandler) LookupItem(name string, vars map[string]string) bool {
	// Allow POST to proceed by returning false, otherwise mark it as existing.
	return h.r.Method != http.MethodPost
}
func (h *syncClientsHandler) NormalizeInput(name string, vars map[string]string) error {
	return nil
}
func (h *syncClientsHandler) Get(name string) error {
	secrets, err := h.s.loadSecrets(h.tx)
	if err != nil {
		return err
	}

	state, err := oathclients.SyncState(h.s.httpClient, h.s.hydraAdminURL, h.cfg.Clients, secrets.ClientSecrets)
	if err != nil {
		state = &cpb.ClientState{
			Status: httputil.NewStatus(codes.Aborted, fmt.Sprintf("getting client sync state failed: %v", err)).Proto(),
		}
		httputil.WriteProtoResp(h.w, state)
		return err
	}

	httputil.WriteProtoResp(h.w, state)
	return nil
}
func (h *syncClientsHandler) Post(name string) error {
	secrets, err := h.s.loadSecrets(h.tx)
	if err != nil {
		return err
	}

	state, err := h.s.syncToHydra(h.cfg.Clients, secrets.ClientSecrets, h.s.hydraSyncFreq, h.tx)
	if err != nil {
		state = &cpb.ClientState{
			Status: httputil.NewStatus(codes.Aborted, fmt.Sprintf("sync clients did not complete: %v", err)).Proto(),
		}
		httputil.WriteProtoResp(h.w, state)
		return err
	}
	httputil.WriteProtoResp(h.w, state)
	return nil
}
func (h *syncClientsHandler) Put(name string) error {
	return fmt.Errorf("PUT not allowed")
}
func (h *syncClientsHandler) Patch(name string) error {
	return fmt.Errorf("PATCH not allowed")
}
func (h *syncClientsHandler) Remove(name string) error {
	return fmt.Errorf("DELETE not allowed")
}
func (h *syncClientsHandler) CheckIntegrity() *status.Status {
	return nil
}
func (h *syncClientsHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return nil
}
