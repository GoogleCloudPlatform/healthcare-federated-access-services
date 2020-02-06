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
	"strconv"

	"github.com/golang/protobuf/proto" /* copybara-comment */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common" /* copybara-comment: common */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/oathclients" /* copybara-comment: oathclients */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/ic/v1" /* copybara-comment: go_proto */
)

// HTTP handler for ".../config"
func (s *Service) configFactory() *common.HandlerFactory {
	return &common.HandlerFactory{
		TypeName:            "config",
		PathPrefix:          configPath,
		HasNamedIdentifiers: false,
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
	cfg, _, id, status, err := c.s.handlerSetup(tx, c.r, noScope, c.input)
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
		c.input.Item.IdentityProviders = make(map[string]*cpb.IdentityProvider)
	}
	if c.input.Item.Clients == nil {
		c.input.Item.Clients = make(map[string]*cpb.Client)
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
	if err := c.s.saveConfig(c.input.Item, desc, typeName, c.r, c.id, c.cfg, c.input.Item, c.input.Modification, tx); err != nil {
		return err
	}
	secrets, err := c.s.loadSecrets(tx)
	if err != nil {
		return err
	}
	// Assumes that secrets don't change within this handler.
	if c.s.useHydra && !common.ClientsEqual(c.input.Item.Clients, c.cfg.Clients) {
		if err = c.s.syncToHydra(c.input.Item.Clients, secrets.ClientSecrets, 0); err != nil {
			return err
		}
	}
	return nil
}

// HTTP handler for ".../config/identityProviders/{name}"
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
	item  *cpb.IdentityProvider
	save  *cpb.IdentityProvider
	cfg   *pb.IcConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func (c *configIDP) Setup(tx storage.Tx, isAdmin bool) (int, error) {
	cfg, _, id, status, err := c.s.handlerSetup(tx, c.r, noScope, c.input)
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
		c.input.Item = &cpb.IdentityProvider{}
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
	c.save = &cpb.IdentityProvider{}
	proto.Merge(c.save, c.item)
	proto.Merge(c.save, c.input.Item)
	c.save.Scopes = c.input.Item.Scopes
	c.save.Ui = c.input.Item.Ui
	c.cfg.IdentityProviders[name] = c.save
	return nil
}
func (c *configIDP) Remove(name string) error {
	delete(c.cfg.IdentityProviders, name)
	c.save = &cpb.IdentityProvider{}
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

// HTTP handler for ".../config/options"
func (s *Service) configOptionsFactory() *common.HandlerFactory {
	return &common.HandlerFactory{
		TypeName:            "configOptions",
		PathPrefix:          configOptionsPath,
		HasNamedIdentifiers: false,
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
	cfg, _, id, status, err := c.s.handlerSetup(tx, c.r, noScope, c.input)
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

// HTTP handler for ".../config/clients/{name}"
// ....

// ConfigHistory implements the HistoryConfig RPC method.
func (s *Service) ConfigHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		common.HandleError(http.StatusBadRequest, fmt.Errorf("request method not supported: %q", r.Method), w)
		return
	}
	// TODO: consider requiring an "admin" scope (modify all admin handlerSetup calls).
	_, _, _, status, err := s.handlerSetup(nil, r, noScope, nil)
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
	_, _, _, status, err := s.handlerSetup(nil, r, noScope, nil)
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
	_, _, _, status, err := s.handlerSetup(nil, r, noScope, nil)
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

	// Reset clients in Hyrdra
	if s.useHydra {
		conf, err := s.loadConfig(nil, storage.DefaultRealm)
		if err != nil {
			common.HandleError(http.StatusServiceUnavailable, err, w)
			return
		}

		secrets, err := s.loadSecrets(nil)
		if err != nil {
			common.HandleError(http.StatusServiceUnavailable, err, w)
			return
		}

		if err := oathclients.ResetClients(s.httpClient, s.hydraAdminURL, conf.Clients, secrets.ClientSecrets); err != nil {
			common.HandleError(http.StatusServiceUnavailable, err, w)
			return
		}
	}
}
