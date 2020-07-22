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

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/check" /* copybara-comment: check */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/handlerfactory" /* copybara-comment: handlerfactory */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/ic/v1" /* copybara-comment: go_proto */
)

// HTTP handler for ".../config"
func (s *Service) configFactory() *handlerfactory.Options {
	return &handlerfactory.Options{
		TypeName:            "config",
		PathPrefix:          configPath,
		HasNamedIdentifiers: false,
		Service: func() handlerfactory.Service {
			return &config{
				s:     s,
				input: &pb.ConfigRequest{},
			}
		},
	}
}

type config struct {
	s     *Service
	input *pb.ConfigRequest
	cfg   *pb.IcConfig
	id    *ga4gh.Identity
}

func (c *config) Setup(r *http.Request, tx storage.Tx) (int, error) {
	cfg, _, id, status, err := c.s.handlerSetup(tx, r, noScope, c.input)
	c.cfg = cfg
	c.id = id
	return status, err
}
func (c *config) LookupItem(r *http.Request, name string, vars map[string]string) bool {
	// Trival name as there is only one config.
	return true
}
func (c *config) NormalizeInput(r *http.Request, name string, vars map[string]string) error {
	if err := httputils.DecodeProtoReq(c.input, r); err != nil {
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
func (c *config) Get(r *http.Request, name string) (proto.Message, error) {
	return makeConfig(c.cfg), nil
}
func (c *config) Post(r *http.Request, name string) (proto.Message, error) {
	return nil, fmt.Errorf("POST not allowed")
}
func (c *config) Put(r *http.Request, name string) (proto.Message, error) {
	if getRealm(r) != storage.DefaultRealm && !check.ClientsEqual(c.input.Item.Clients, c.cfg.Clients) {
		return nil, status.Errorf(codes.PermissionDenied, "modify clients is only allowed on master realm")
	}

	if c.cfg.Version != c.input.Item.Version {
		// TODO: consider upgrading older config versions automatically.
		return nil, fmt.Errorf("PUT of config version %q mismatched with existing config version %q", c.input.Item.Version, c.cfg.Version)
	}
	// Retain the revision number (it will be incremented upon saving).
	c.input.Item.Revision = c.cfg.Revision
	return nil, nil
}
func (c *config) Patch(r *http.Request, name string) (proto.Message, error) {
	return nil, fmt.Errorf("PATCH not allowed")
}
func (c *config) Remove(r *http.Request, name string) (proto.Message, error) {
	return nil, fmt.Errorf("DELETE not allowed")
}
func (c *config) CheckIntegrity(r *http.Request) *status.Status {
	bad := codes.InvalidArgument
	if err := check.ValidToWriteConfig(getRealm(r), c.cfg.Options.ReadOnlyMasterRealm); err != nil {
		return httputils.NewStatus(bad, err.Error())
	}
	if len(c.input.Item.Version) == 0 {
		return httputils.NewStatus(bad, "missing config version")
	}
	if c.input.Item.Revision <= 0 {
		return httputils.NewStatus(bad, "invalid config revision")
	}
	if err := configRevision(c.input.Modification, c.cfg); err != nil {
		return httputils.NewStatus(bad, err.Error())
	}
	if err := c.s.checkConfigIntegrity(c.input.Item); err != nil {
		return httputils.NewStatus(bad, err.Error())
	}
	return nil
}
func (c *config) Save(r *http.Request, tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	if err := c.s.saveConfig(c.input.Item, desc, typeName, r, c.id, c.cfg, c.input.Item, c.input.Modification, tx); err != nil {
		return err
	}
	secrets, err := c.s.loadSecrets(tx)
	if err != nil {
		return err
	}
	// Assumes that secrets don't change within this handler.
	if c.s.useHydra && !check.ClientsEqual(c.input.Item.Clients, c.cfg.Clients) {
		if _, err = c.s.syncToHydra(c.input.Item.Clients, secrets.ClientSecrets, 0, tx); err != nil {
			return err
		}
	}
	return nil
}

// HTTP handler for ".../config/identityProviders/{name}"
func (s *Service) configIdpFactory() *handlerfactory.Options {
	return &handlerfactory.Options{
		TypeName:            "configIDP",
		PathPrefix:          configIdentityProvidersPath,
		HasNamedIdentifiers: true,
		Service: func() handlerfactory.Service {
			return &configIDP{
				s:     s,
				input: &pb.ConfigIdentityProviderRequest{},
			}
		},
	}
}

type configIDP struct {
	s     *Service
	r     *http.Request
	input *pb.ConfigIdentityProviderRequest
	item  *cpb.IdentityProvider
	save  *cpb.IdentityProvider
	cfg   *pb.IcConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func (c *configIDP) Setup(r *http.Request, tx storage.Tx) (int, error) {
	cfg, _, id, status, err := c.s.handlerSetup(tx, r, noScope, c.input)
	c.cfg = cfg
	c.id = id
	c.tx = tx
	return status, err
}
func (c *configIDP) LookupItem(r *http.Request, name string, vars map[string]string) bool {
	if item, ok := c.cfg.IdentityProviders[name]; ok {
		c.item = item
		return true
	}
	return false
}
func (c *configIDP) NormalizeInput(r *http.Request, name string, vars map[string]string) error {
	if err := httputils.DecodeProtoReq(c.input, r); err != nil {
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
func (c *configIDP) Get(r *http.Request, name string) (proto.Message, error) {
	return c.item, nil
}
func (c *configIDP) Post(r *http.Request, name string) (proto.Message, error) {
	c.save = c.input.Item
	c.cfg.IdentityProviders[name] = c.save
	return nil, nil
}
func (c *configIDP) Put(r *http.Request, name string) (proto.Message, error) {
	c.save = c.input.Item
	c.cfg.IdentityProviders[name] = c.save
	return nil, nil
}
func (c *configIDP) Patch(r *http.Request, name string) (proto.Message, error) {
	c.save = &cpb.IdentityProvider{}
	proto.Merge(c.save, c.item)
	proto.Merge(c.save, c.input.Item)
	c.save.Scopes = c.input.Item.Scopes
	c.save.Ui = c.input.Item.Ui
	c.cfg.IdentityProviders[name] = c.save
	return nil, nil
}
func (c *configIDP) Remove(r *http.Request, name string) (proto.Message, error) {
	delete(c.cfg.IdentityProviders, name)
	c.save = &cpb.IdentityProvider{}
	return nil, nil
}
func (c *configIDP) CheckIntegrity(r *http.Request) *status.Status {
	bad := codes.InvalidArgument
	if err := check.ValidToWriteConfig(getRealm(r), c.cfg.Options.ReadOnlyMasterRealm); err != nil {
		return httputils.NewStatus(bad, err.Error())
	}
	if err := configRevision(c.input.Modification, c.cfg); err != nil {
		return httputils.NewStatus(bad, err.Error())
	}
	if err := c.s.checkConfigIntegrity(c.cfg); err != nil {
		return httputils.NewStatus(bad, err.Error())
	}
	return nil
}
func (c *configIDP) Save(r *http.Request, tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	if c.save == nil || (c.input.Modification != nil && c.input.Modification.DryRun) {
		return nil
	}
	if err := c.s.saveConfig(c.cfg, desc, typeName, r, c.id, c.item, c.save, c.input.Modification, c.tx); err != nil {
		return err
	}
	return nil
}

// HTTP handler for ".../config/options"
func (s *Service) configOptionsFactory() *handlerfactory.Options {
	return &handlerfactory.Options{
		TypeName:            "configOptions",
		PathPrefix:          configOptionsPath,
		HasNamedIdentifiers: false,
		Service: func() handlerfactory.Service {
			return &configOptions{
				s:     s,
				input: &pb.ConfigOptionsRequest{},
			}
		},
	}
}

type configOptions struct {
	s     *Service
	r     *http.Request
	input *pb.ConfigOptionsRequest
	item  *pb.ConfigOptions
	save  *pb.ConfigOptions
	cfg   *pb.IcConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func (c *configOptions) Setup(r *http.Request, tx storage.Tx) (int, error) {
	cfg, _, id, status, err := c.s.handlerSetup(tx, r, noScope, c.input)
	c.cfg = cfg
	c.id = id
	c.tx = tx
	return status, err
}

func (c *configOptions) LookupItem(r *http.Request, name string, vars map[string]string) bool {
	c.item = c.cfg.Options
	return true
}

func (c *configOptions) NormalizeInput(r *http.Request, name string, vars map[string]string) error {
	if err := httputils.DecodeProtoReq(c.input, r); err != nil {
		return err
	}
	if c.input.Item == nil {
		c.input.Item = &pb.ConfigOptions{}
	}
	c.input.Item = receiveConfigOptions(c.input.Item)
	return nil
}

func (c *configOptions) Get(r *http.Request, name string) (proto.Message, error) {
	return makeConfigOptions(c.item), nil
}

func (c *configOptions) Post(r *http.Request, name string) (proto.Message, error) {
	c.save = c.input.Item
	c.cfg.Options = c.save
	return nil, nil
}

func (c *configOptions) Put(r *http.Request, name string) (proto.Message, error) {
	c.save = c.input.Item
	c.cfg.Options = c.save
	return nil, nil
}

func (c *configOptions) Patch(r *http.Request, name string) (proto.Message, error) {
	c.save = &pb.ConfigOptions{}
	proto.Merge(c.save, c.item)
	proto.Merge(c.save, c.input.Item)
	c.save.ReadOnlyMasterRealm = c.input.Item.ReadOnlyMasterRealm
	c.cfg.Options = c.save
	return nil, nil
}

func (c *configOptions) Remove(r *http.Request, name string) (proto.Message, error) {
	return nil, fmt.Errorf("DELETE not allowed")
}

func (c *configOptions) CheckIntegrity(r *http.Request) *status.Status {
	bad := codes.InvalidArgument
	if err := check.ValidToWriteConfig(getRealm(r), c.cfg.Options.ReadOnlyMasterRealm); err != nil {
		return httputils.NewStatus(bad, err.Error())
	}
	if err := configRevision(c.input.Modification, c.cfg); err != nil {
		return httputils.NewStatus(bad, err.Error())
	}
	if err := c.s.checkConfigIntegrity(c.cfg); err != nil {
		return httputils.NewStatus(bad, err.Error())
	}
	return nil
}

func (c *configOptions) Save(r *http.Request, tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	if c.save == nil || (c.input.Modification != nil && c.input.Modification.DryRun) {
		return nil
	}
	if err := c.s.saveConfig(c.cfg, desc, typeName, r, c.id, c.item, c.save, c.input.Modification, c.tx); err != nil {
		return err
	}
	return nil
}

// HTTP handler for ".../config/clients/{name}"
// ....

// HTTP handler for ".../config/options"

// ConfigHistory implements the HistoryConfig RPC method.
func (s *Service) ConfigHistory(w http.ResponseWriter, r *http.Request) {
	// TODO: consider requiring an "admin" scope (modify all admin handlerSetup calls).
	_, _, _, sts, err := s.handlerSetup(nil, r, noScope, nil)
	if err != nil {
		httputils.WriteError(w, status.Errorf(httputils.RPCCode(sts), "%v", err))
		return
	}
	h, sts, err := storage.GetHistory(s.store, storage.ConfigDatatype, getRealm(r), storage.DefaultUser, storage.DefaultID, r)
	if err != nil {
		httputils.WriteError(w, status.Errorf(httputils.RPCCode(sts), "%v", err))
	}
	httputils.WriteResp(w, h)
}

// ConfigHistoryRevision implements the HistoryRevisionConfig RPC method.
func (s *Service) ConfigHistoryRevision(w http.ResponseWriter, r *http.Request) {
	name := getName(r)
	rev, err := strconv.ParseInt(name, 10, 64)
	if err != nil {
		httputils.WriteError(w, status.Errorf(codes.InvalidArgument, "invalid history revision: %q (must be a positive integer)", name))
		return
	}
	_, _, _, sts, err := s.handlerSetup(nil, r, noScope, nil)
	if err != nil {
		httputils.WriteError(w, status.Errorf(httputils.RPCCode(sts), "%v", err))
		return
	}
	cfg := &pb.IcConfig{}
	if sts, err := s.realmReadTx(storage.ConfigDatatype, getRealm(r), storage.DefaultUser, storage.DefaultID, rev, cfg, nil); err != nil {
		httputils.WriteError(w, status.Errorf(httputils.RPCCode(sts), "%v", err))
		return
	}
	httputils.WriteResp(w, cfg)
}

// ConfigReset implements the corresponding method in the IC API.
func (s *Service) ConfigReset(w http.ResponseWriter, r *http.Request) {
	_, _, _, sts, err := s.handlerSetup(nil, r, noScope, nil)
	if err != nil {
		httputils.WriteError(w, status.Errorf(httputils.RPCCode(sts), "%v", err))
		return
	}
	if _, err = s.store.Wipe(r.Context(), storage.AllRealms, 0, 0); err != nil {
		httputils.WriteError(w, status.Errorf(codes.Internal, "%v", err))
		return
	}
	if err = ImportConfig(s.store, s.serviceName, nil, true, true, true); err != nil {
		httputils.WriteError(w, status.Errorf(codes.Internal, "%v", err))
		return
	}

	// Reset clients in Hyrdra
	if s.useHydra {
		if getRealm(r) != storage.DefaultRealm {
			return
		}
		conf, err := s.loadConfig(nil, storage.DefaultRealm)
		if err != nil {
			httputils.WriteError(w, status.Errorf(codes.Unavailable, "%v", err))
			return
		}

		secrets, err := s.loadSecrets(nil)
		if err != nil {
			httputils.WriteError(w, status.Errorf(codes.Unavailable, "%v", err))
			return
		}

		if _, err := s.syncToHydra(conf.Clients, secrets.ClientSecrets, 0, nil); err != nil {
			httputils.WriteError(w, status.Errorf(codes.Unavailable, "%v", err))
			return
		}
	}
}
