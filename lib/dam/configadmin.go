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
	"fmt"
	"net/http"
	"sort"
	"strconv"

	"github.com/golang/protobuf/proto" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/check" /* copybara-comment: check */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
)

func (s *Service) configFactory() *httputil.HandlerFactory {
	return &httputil.HandlerFactory{
		TypeName:            "config",
		PathPrefix:          configPath,
		HasNamedIdentifiers: false,
		NewHandler: func(w http.ResponseWriter, r *http.Request) httputil.HandlerInterface {
			return NewConfigHandler(s, w, r)
		},
	}
}

type configHandler struct {
	s     *Service
	w     http.ResponseWriter
	r     *http.Request
	input *pb.ConfigRequest
	save  *pb.DamConfig
	cfg   *pb.DamConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func NewConfigHandler(s *Service, w http.ResponseWriter, r *http.Request) *configHandler {
	return &configHandler{
		s:     s,
		w:     w,
		r:     r,
		input: &pb.ConfigRequest{},
	}
}
func (h *configHandler) Setup(tx storage.Tx) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, h.r, noScope, h.input)
	h.tx = tx
	h.cfg = cfg
	h.id = id
	return status, err
}
func (h *configHandler) LookupItem(name string, vars map[string]string) bool {
	// Trival name as there is only one config and it was fetched during Setup().
	return true
}
func (h *configHandler) NormalizeInput(name string, vars map[string]string) error {
	if err := httputil.GetRequest(h.input, h.r); err != nil {
		return err
	}
	if h.input.Item == nil {
		h.input.Item = &pb.DamConfig{}
	}
	if h.input.Modification == nil {
		h.input.Modification = &pb.ConfigModification{}
	}
	if h.input.Item.Clients == nil {
		h.input.Item.Clients = make(map[string]*cpb.Client)
	}
	if h.input.Item.Options == nil {
		h.input.Item.Options = &pb.ConfigOptions{}
	}
	h.input.Item.Options = receiveConfigOptions(h.input.Item.Options, h.cfg)
	normalizeConfig(h.input.Item)
	return nil
}
func (h *configHandler) Get(name string) error {
	httputil.SendResponse(makeConfig(h.cfg), h.w)
	return nil
}
func (h *configHandler) Post(name string) error {
	return fmt.Errorf("POST not allowed")
}
func (h *configHandler) Put(name string) error {
	if h.cfg.Version != h.input.Item.Version {
		// TODO: consider upgrading older config versions automatically.
		return fmt.Errorf("PUT of config version %q mismatched with existing config version %q", h.input.Item.Version, h.cfg.Version)
	}
	h.save = receiveConfig(h.input.Item, h.cfg)
	// Retain the revision number (it will be incremented upon saving).
	h.save.Revision = h.cfg.Revision
	return nil
}
func (h *configHandler) Patch(name string) error {
	return fmt.Errorf("PATCH not allowed")
}
func (h *configHandler) Remove(name string) error {
	return fmt.Errorf("DELETE not allowed")
}
func (h *configHandler) CheckIntegrity() *status.Status {
	return h.s.configCheckIntegrity(h.save, h.input.Modification, h.r)
}
func (h *configHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	if err := h.s.saveConfig(h.save, desc, typeName, h.r, h.id, h.cfg, h.save, h.input.Modification, tx); err != nil {
		return err
	}
	secrets, err := h.s.loadSecrets(tx)
	if err != nil {
		return err
	}
	// Assumes that secrets don't change within this handler.
	if h.s.useHydra && !check.ClientsEqual(h.cfg.Clients, h.save.Clients) {
		if err = h.s.syncToHydra(h.save.Clients, secrets.ClientSecrets, 0); err != nil {
			return err
		}
	}
	if !proto.Equal(h.cfg.Options, h.save.Options) {
		h.s.updateWarehouseOptions(h.save.Options, getRealm(h.r))
		return h.s.registerProject(h.save.Options.GcpServiceAccountProject)
	}
	return nil
}

//////////////////////////////////////////////////////////////////

func (s *Service) configOptionsFactory() *httputil.HandlerFactory {
	return &httputil.HandlerFactory{
		TypeName:            "configOptions",
		PathPrefix:          configOptionsPath,
		HasNamedIdentifiers: false,
		NewHandler: func(w http.ResponseWriter, r *http.Request) httputil.HandlerInterface {
			return NewConfigOptionsHandler(s, w, r)
		},
	}
}

type configOptionsHandler struct {
	s     *Service
	w     http.ResponseWriter
	r     *http.Request
	input *pb.ConfigOptionsRequest
	item  *pb.ConfigOptions
	orig  *pb.ConfigOptions
	save  *pb.ConfigOptions
	cfg   *pb.DamConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func NewConfigOptionsHandler(s *Service, w http.ResponseWriter, r *http.Request) *configOptionsHandler {
	return &configOptionsHandler{
		s:     s,
		w:     w,
		r:     r,
		input: &pb.ConfigOptionsRequest{},
	}
}
func (h *configOptionsHandler) Setup(tx storage.Tx) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, h.r, noScope, h.input)
	h.cfg = cfg
	h.id = id
	h.tx = tx
	return status, err
}
func (h *configOptionsHandler) LookupItem(name string, vars map[string]string) bool {
	h.item = h.cfg.Options
	return true
}
func (h *configOptionsHandler) NormalizeInput(name string, vars map[string]string) error {
	if err := httputil.GetRequest(h.input, h.r); err != nil {
		return err
	}
	if h.input.Item == nil {
		h.input.Item = &pb.ConfigOptions{}
	}
	h.input.Item = receiveConfigOptions(h.input.Item, h.cfg)
	return nil
}
func (h *configOptionsHandler) Get(name string) error {
	httputil.SendResponse(makeConfigOptions(h.item), h.w)
	return nil
}
func (h *configOptionsHandler) Post(name string) error {
	return fmt.Errorf("POST not allowed")
}
func (h *configOptionsHandler) Put(name string) error {
	h.orig = &pb.ConfigOptions{}
	proto.Merge(h.orig, h.item)
	h.cfg.Options = h.input.Item
	h.save = h.input.Item
	return nil
}
func (h *configOptionsHandler) Patch(name string) error {
	h.orig = &pb.ConfigOptions{}
	proto.Merge(h.orig, h.item)
	proto.Merge(h.item, h.input.Item)
	h.item.ReadOnlyMasterRealm = h.input.Item.ReadOnlyMasterRealm
	h.save = h.item
	return nil
}
func (h *configOptionsHandler) Remove(name string) error {
	return fmt.Errorf("DELETE not allowed")
}
func (h *configOptionsHandler) CheckIntegrity() *status.Status {
	return h.s.configCheckIntegrity(h.cfg, h.input.Modification, h.r)
}
func (h *configOptionsHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	if err := h.s.saveConfig(h.cfg, desc, typeName, h.r, h.id, h.item, h.save, h.input.Modification, h.tx); err != nil {
		return err
	}
	if h.orig != nil && !proto.Equal(h.orig, h.save) {
		h.s.updateWarehouseOptions(h.save, getRealm(h.r))
		return h.s.registerProject(h.save.GcpServiceAccountProject)
	}
	return nil
}

//////////////////////////////////////////////////////////////////

func (s *Service) configResourceFactory() *httputil.HandlerFactory {
	return &httputil.HandlerFactory{
		TypeName:            "configResource",
		PathPrefix:          configResourcePath,
		HasNamedIdentifiers: true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) httputil.HandlerInterface {
			return NewConfigResourceHandler(s, w, r)
		},
	}
}

type configResourceHandler struct {
	s     *Service
	w     http.ResponseWriter
	r     *http.Request
	input *pb.ConfigResourceRequest
	item  *pb.Resource
	save  *pb.Resource
	cfg   *pb.DamConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func NewConfigResourceHandler(s *Service, w http.ResponseWriter, r *http.Request) *configResourceHandler {
	return &configResourceHandler{
		s:     s,
		w:     w,
		r:     r,
		input: &pb.ConfigResourceRequest{},
	}
}
func (h *configResourceHandler) Setup(tx storage.Tx) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, h.r, noScope, h.input)
	h.cfg = cfg
	h.id = id
	h.tx = tx
	return status, err
}
func (h *configResourceHandler) LookupItem(name string, vars map[string]string) bool {
	item, ok := h.cfg.Resources[name]
	if !ok {
		return false
	}
	h.item = item
	return true
}
func (h *configResourceHandler) NormalizeInput(name string, vars map[string]string) error {
	if err := httputil.GetRequest(h.input, h.r); err != nil {
		return err
	}
	if h.input.Item == nil {
		h.input.Item = &pb.Resource{}
	}
	if h.input.Item.Ui == nil {
		h.input.Item.Ui = make(map[string]string)
	}
	h.input.Item = receiveResource(h.input.Item)
	return nil
}
func (h *configResourceHandler) Get(name string) error {
	httputil.SendResponse(h.item, h.w)
	return nil
}
func (h *configResourceHandler) Post(name string) error {
	h.cfg.Resources[name] = h.input.Item
	h.save = h.input.Item
	return nil
}
func (h *configResourceHandler) Put(name string) error {
	h.cfg.Resources[name] = h.input.Item
	h.save = h.input.Item
	return nil
}
func (h *configResourceHandler) Patch(name string) error {
	proto.Merge(h.item, h.input.Item)
	h.item.Views = h.input.Item.Views
	h.item.Ui = h.input.Item.Ui
	h.save = h.item
	return nil
}
func (h *configResourceHandler) Remove(name string) error {
	rmTestResource(h.cfg, name)
	delete(h.cfg.Resources, name)
	h.save = &pb.Resource{}
	return nil
}
func (h *configResourceHandler) CheckIntegrity() *status.Status {
	return h.s.configCheckIntegrity(h.cfg, h.input.Modification, h.r)
}
func (h *configResourceHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return h.s.saveConfig(h.cfg, desc, typeName, h.r, h.id, h.item, h.save, h.input.Modification, h.tx)
}

//////////////////////////////////////////////////////////////////

func (s *Service) configViewFactory() *httputil.HandlerFactory {
	return &httputil.HandlerFactory{
		TypeName:            "configView",
		PathPrefix:          configViewPath,
		HasNamedIdentifiers: true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) httputil.HandlerInterface {
			return NewConfigViewHandler(s, w, r)
		},
	}
}

type configViewHandler struct {
	s       *Service
	w       http.ResponseWriter
	r       *http.Request
	input   *pb.ConfigViewRequest
	item    *pb.View
	save    *pb.View
	res     *pb.Resource
	resName string
	cfg     *pb.DamConfig
	id      *ga4gh.Identity
	tx      storage.Tx
}

func NewConfigViewHandler(s *Service, w http.ResponseWriter, r *http.Request) *configViewHandler {
	return &configViewHandler{
		s:     s,
		w:     w,
		r:     r,
		input: &pb.ConfigViewRequest{},
	}
}
func (h *configViewHandler) Setup(tx storage.Tx) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, h.r, noScope, h.input)
	h.cfg = cfg
	h.id = id
	h.tx = tx
	return status, err
}
func (h *configViewHandler) LookupItem(name string, vars map[string]string) bool {
	resName, ok := vars["resource"]
	if !ok {
		return false
	}
	res, ok := h.cfg.Resources[resName]
	if !ok {
		return false
	}
	h.res = res
	h.resName = resName
	item, ok := res.Views[name]
	if !ok {
		return false
	}
	h.item = item
	return true
}
func (h *configViewHandler) NormalizeInput(name string, vars map[string]string) error {
	if err := httputil.GetRequest(h.input, h.r); err != nil {
		return err
	}
	if h.input.Item == nil {
		h.input.Item = &pb.View{}
	}
	h.input.Item = receiveView(h.input.Item)
	return nil
}
func (h *configViewHandler) Get(name string) error {
	httputil.SendResponse(h.item, h.w)
	return nil
}
func (h *configViewHandler) Post(name string) error {
	h.cfg.Resources[h.resName].Views[name] = h.input.Item
	h.save = h.input.Item
	return nil
}
func (h *configViewHandler) Put(name string) error {
	h.cfg.Resources[h.resName].Views[name] = h.input.Item
	h.save = h.input.Item
	return nil
}
func (h *configViewHandler) Patch(name string) error {
	proto.Merge(h.item, h.input.Item)
	h.item.Items = h.input.Item.Items
	h.item.AccessRoles = h.input.Item.AccessRoles
	h.item.Ui = h.input.Item.Ui
	h.save = h.item
	return nil
}
func (h *configViewHandler) Remove(name string) error {
	rmTestView(h.cfg, h.resName, name)
	delete(h.cfg.Resources[h.resName].Views, name)
	h.save = &pb.View{}
	return nil
}
func (h *configViewHandler) CheckIntegrity() *status.Status {
	return h.s.configCheckIntegrity(h.cfg, h.input.Modification, h.r)
}
func (h *configViewHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return h.s.saveConfig(h.cfg, desc, typeName, h.r, h.id, h.item, h.save, h.input.Modification, h.tx)
}

//////////////////////////////////////////////////////////////////

func (s *Service) configIssuerFactory() *httputil.HandlerFactory {
	return &httputil.HandlerFactory{
		TypeName:            "configTrustedPassportIssuer",
		PathPrefix:          configTrustedPassportIssuerPath,
		HasNamedIdentifiers: true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) httputil.HandlerInterface {
			return NewConfigIssuerHandler(s, w, r)
		},
	}
}

type configIssuerHandler struct {
	s     *Service
	w     http.ResponseWriter
	r     *http.Request
	input *pb.ConfigTrustedPassportIssuerRequest
	item  *pb.TrustedPassportIssuer
	save  *pb.TrustedPassportIssuer
	cfg   *pb.DamConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func NewConfigIssuerHandler(s *Service, w http.ResponseWriter, r *http.Request) *configIssuerHandler {
	return &configIssuerHandler{
		s:     s,
		w:     w,
		r:     r,
		input: &pb.ConfigTrustedPassportIssuerRequest{},
	}
}
func (h *configIssuerHandler) Setup(tx storage.Tx) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, h.r, noScope, h.input)
	h.cfg = cfg
	h.id = id
	h.tx = tx
	return status, err
}
func (h *configIssuerHandler) LookupItem(name string, vars map[string]string) bool {
	item, ok := h.cfg.TrustedPassportIssuers[name]
	if !ok {
		return false
	}
	h.item = item
	return true
}
func (h *configIssuerHandler) NormalizeInput(name string, vars map[string]string) error {
	if err := httputil.GetRequest(h.input, h.r); err != nil {
		return err
	}
	if h.input.Item == nil {
		h.input.Item = &pb.TrustedPassportIssuer{}
	}
	if h.input.Item.Ui == nil {
		h.input.Item.Ui = make(map[string]string)
	}
	return nil
}
func (h *configIssuerHandler) Get(name string) error {
	httputil.SendResponse(h.item, h.w)
	return nil
}
func (h *configIssuerHandler) Post(name string) error {
	h.cfg.TrustedPassportIssuers[name] = h.input.Item
	h.save = h.input.Item
	return nil
}
func (h *configIssuerHandler) Put(name string) error {
	h.cfg.TrustedPassportIssuers[name] = h.input.Item
	h.save = h.input.Item
	return nil
}
func (h *configIssuerHandler) Patch(name string) error {
	proto.Merge(h.item, h.input.Item)
	h.item.Ui = h.input.Item.Ui
	h.save = h.item
	return nil
}
func (h *configIssuerHandler) Remove(name string) error {
	delete(h.cfg.TrustedPassportIssuers, name)
	h.save = &pb.TrustedPassportIssuer{}
	return nil
}
func (h *configIssuerHandler) CheckIntegrity() *status.Status {
	return h.s.configCheckIntegrity(h.cfg, h.input.Modification, h.r)
}
func (h *configIssuerHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return h.s.saveConfig(h.cfg, desc, typeName, h.r, h.id, h.item, h.save, h.input.Modification, h.tx)
}

//////////////////////////////////////////////////////////////////

func (s *Service) configSourceFactory() *httputil.HandlerFactory {
	return &httputil.HandlerFactory{
		TypeName:            "configTrustedSource",
		PathPrefix:          configTrustedSourcePath,
		HasNamedIdentifiers: true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) httputil.HandlerInterface {
			return NewConfigSourceHandler(s, w, r)
		},
	}
}

type configSourceHandler struct {
	s     *Service
	w     http.ResponseWriter
	r     *http.Request
	input *pb.ConfigTrustedSourceRequest
	item  *pb.TrustedSource
	save  *pb.TrustedSource
	cfg   *pb.DamConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func NewConfigSourceHandler(s *Service, w http.ResponseWriter, r *http.Request) *configSourceHandler {
	return &configSourceHandler{
		s:     s,
		w:     w,
		r:     r,
		input: &pb.ConfigTrustedSourceRequest{},
	}
}
func (h *configSourceHandler) Setup(tx storage.Tx) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, h.r, noScope, h.input)
	h.cfg = cfg
	h.id = id
	h.tx = tx
	return status, err
}
func (h *configSourceHandler) LookupItem(name string, vars map[string]string) bool {
	item, ok := h.cfg.TrustedSources[name]
	if !ok {
		return false
	}
	h.item = item
	return true
}
func (h *configSourceHandler) NormalizeInput(name string, vars map[string]string) error {
	if err := httputil.GetRequest(h.input, h.r); err != nil {
		return err
	}
	if h.input.Item == nil {
		h.input.Item = &pb.TrustedSource{}
	}
	if h.input.Item.Ui == nil {
		h.input.Item.Ui = make(map[string]string)
	}
	return nil
}
func (h *configSourceHandler) Get(name string) error {
	httputil.SendResponse(h.item, h.w)
	return nil
}
func (h *configSourceHandler) Post(name string) error {
	h.cfg.TrustedSources[name] = h.input.Item
	h.save = h.input.Item
	return nil
}
func (h *configSourceHandler) Put(name string) error {
	h.cfg.TrustedSources[name] = h.input.Item
	h.save = h.input.Item
	return nil
}
func (h *configSourceHandler) Patch(name string) error {
	proto.Merge(h.item, h.input.Item)
	h.item.Sources = h.input.Item.Sources
	h.item.Claims = h.input.Item.Claims
	h.item.Ui = h.input.Item.Ui
	h.save = h.item
	return nil
}
func (h *configSourceHandler) Remove(name string) error {
	delete(h.cfg.TrustedSources, name)
	h.save = &pb.TrustedSource{}
	return nil
}
func (h *configSourceHandler) CheckIntegrity() *status.Status {
	return h.s.configCheckIntegrity(h.cfg, h.input.Modification, h.r)
}
func (h *configSourceHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return h.s.saveConfig(h.cfg, desc, typeName, h.r, h.id, h.item, h.save, h.input.Modification, h.tx)
}

//////////////////////////////////////////////////////////////////

func (s *Service) configPolicyFactory() *httputil.HandlerFactory {
	return &httputil.HandlerFactory{
		TypeName:            "configPolicy",
		PathPrefix:          configPolicyPath,
		HasNamedIdentifiers: true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) httputil.HandlerInterface {
			return NewConfigPolicyHandler(s, w, r)
		},
	}
}

type configPolicyHandler struct {
	s     *Service
	w     http.ResponseWriter
	r     *http.Request
	input *pb.ConfigPolicyRequest
	item  *pb.Policy
	save  *pb.Policy
	cfg   *pb.DamConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func NewConfigPolicyHandler(s *Service, w http.ResponseWriter, r *http.Request) *configPolicyHandler {
	return &configPolicyHandler{
		s:     s,
		w:     w,
		r:     r,
		input: &pb.ConfigPolicyRequest{},
	}
}
func (h *configPolicyHandler) Setup(tx storage.Tx) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, h.r, noScope, h.input)
	h.cfg = cfg
	h.id = id
	h.tx = tx
	return status, err
}
func (h *configPolicyHandler) LookupItem(name string, vars map[string]string) bool {
	item, ok := h.cfg.Policies[name]
	if !ok {
		return false
	}
	h.item = item
	return true
}
func (h *configPolicyHandler) NormalizeInput(name string, vars map[string]string) error {
	if err := httputil.GetRequest(h.input, h.r); err != nil {
		return err
	}
	if h.input.Item == nil {
		h.input.Item = &pb.Policy{}
	}
	if h.input.Item.Ui == nil {
		h.input.Item.Ui = make(map[string]string)
	}
	return nil
}
func (h *configPolicyHandler) Get(name string) error {
	httputil.SendResponse(h.item, h.w)
	return nil
}
func (h *configPolicyHandler) Post(name string) error {
	h.cfg.Policies[name] = h.input.Item
	h.save = h.input.Item
	return nil
}
func (h *configPolicyHandler) Put(name string) error {
	h.cfg.Policies[name] = h.input.Item
	h.save = h.input.Item
	return nil
}
func (h *configPolicyHandler) Patch(name string) error {
	proto.Merge(h.item, h.input.Item)
	h.item.AnyOf = h.input.Item.AnyOf
	h.item.Ui = h.input.Item.Ui
	h.save = h.item
	return nil
}
func (h *configPolicyHandler) Remove(name string) error {
	delete(h.cfg.Policies, name)
	h.save = &pb.Policy{}
	return nil
}
func (h *configPolicyHandler) CheckIntegrity() *status.Status {
	return h.s.configCheckIntegrity(h.cfg, h.input.Modification, h.r)
}
func (h *configPolicyHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return h.s.saveConfig(h.cfg, desc, typeName, h.r, h.id, h.item, h.save, h.input.Modification, h.tx)
}

//////////////////////////////////////////////////////////////////

func (s *Service) configClaimDefinitionFactory() *httputil.HandlerFactory {
	return &httputil.HandlerFactory{
		TypeName:            "configClaimDefinition",
		PathPrefix:          configClaimDefPath,
		HasNamedIdentifiers: true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) httputil.HandlerInterface {
			return NewConfigClaimDefinitionHandler(s, w, r)
		},
	}
}

type configClaimDefinitionHandler struct {
	s     *Service
	w     http.ResponseWriter
	r     *http.Request
	input *pb.ConfigClaimDefinitionRequest
	item  *pb.ClaimDefinition
	save  *pb.ClaimDefinition
	cfg   *pb.DamConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func NewConfigClaimDefinitionHandler(s *Service, w http.ResponseWriter, r *http.Request) *configClaimDefinitionHandler {
	return &configClaimDefinitionHandler{
		s:     s,
		w:     w,
		r:     r,
		input: &pb.ConfigClaimDefinitionRequest{},
	}
}
func (h *configClaimDefinitionHandler) Setup(tx storage.Tx) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, h.r, noScope, h.input)
	h.cfg = cfg
	h.id = id
	h.tx = tx
	return status, err
}
func (h *configClaimDefinitionHandler) LookupItem(name string, vars map[string]string) bool {
	item, ok := h.cfg.ClaimDefinitions[name]
	if !ok {
		return false
	}
	h.item = item
	return true
}
func (h *configClaimDefinitionHandler) NormalizeInput(name string, vars map[string]string) error {
	if err := httputil.GetRequest(h.input, h.r); err != nil {
		return err
	}
	if h.input.Item == nil {
		h.input.Item = &pb.ClaimDefinition{}
	}
	if h.input.Item.Ui == nil {
		h.input.Item.Ui = make(map[string]string)
	}
	return nil
}
func (h *configClaimDefinitionHandler) Get(name string) error {
	httputil.SendResponse(h.item, h.w)
	return nil
}
func (h *configClaimDefinitionHandler) Post(name string) error {
	h.cfg.ClaimDefinitions[name] = h.input.Item
	h.save = h.input.Item
	return nil
}
func (h *configClaimDefinitionHandler) Put(name string) error {
	h.cfg.ClaimDefinitions[name] = h.input.Item
	h.save = h.input.Item
	return nil
}
func (h *configClaimDefinitionHandler) Patch(name string) error {
	proto.Merge(h.item, h.input.Item)
	h.item.Ui = h.input.Item.Ui
	h.save = h.item
	return nil
}
func (h *configClaimDefinitionHandler) Remove(name string) error {
	delete(h.cfg.ClaimDefinitions, name)
	h.save = &pb.ClaimDefinition{}
	return nil
}
func (h *configClaimDefinitionHandler) CheckIntegrity() *status.Status {
	return h.s.configCheckIntegrity(h.cfg, h.input.Modification, h.r)
}
func (h *configClaimDefinitionHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return h.s.saveConfig(h.cfg, desc, typeName, h.r, h.id, h.item, h.save, h.input.Modification, h.tx)
}

//////////////////////////////////////////////////////////////////

func (s *Service) configServiceTemplateFactory() *httputil.HandlerFactory {
	return &httputil.HandlerFactory{
		TypeName:            "configServiceTemplate",
		PathPrefix:          configServiceTemplatePath,
		HasNamedIdentifiers: true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) httputil.HandlerInterface {
			return NewConfigServiceTemplateHandler(s, w, r)
		},
	}
}

type configServiceTemplateHandler struct {
	s     *Service
	w     http.ResponseWriter
	r     *http.Request
	input *pb.ConfigServiceTemplateRequest
	item  *pb.ServiceTemplate
	save  *pb.ServiceTemplate
	cfg   *pb.DamConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func NewConfigServiceTemplateHandler(s *Service, w http.ResponseWriter, r *http.Request) *configServiceTemplateHandler {
	return &configServiceTemplateHandler{
		s:     s,
		w:     w,
		r:     r,
		input: &pb.ConfigServiceTemplateRequest{},
	}
}
func (h *configServiceTemplateHandler) Setup(tx storage.Tx) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, h.r, noScope, h.input)
	h.cfg = cfg
	h.id = id
	h.tx = tx
	return status, err
}
func (h *configServiceTemplateHandler) LookupItem(name string, vars map[string]string) bool {
	item, ok := h.cfg.ServiceTemplates[name]
	if !ok {
		return false
	}
	h.item = item
	return true
}
func (h *configServiceTemplateHandler) NormalizeInput(name string, vars map[string]string) error {
	if err := httputil.GetRequest(h.input, h.r); err != nil {
		return err
	}
	if h.input.Item == nil {
		h.input.Item = &pb.ServiceTemplate{}
	}
	if h.input.Item.Interfaces == nil {
		h.input.Item.Interfaces = make(map[string]string)
	}
	if h.input.Item.ServiceRoles == nil {
		h.input.Item.ServiceRoles = make(map[string]*pb.ServiceRole)
	}
	if h.input.Item.Ui == nil {
		h.input.Item.Ui = make(map[string]string)
	}
	return nil
}
func (h *configServiceTemplateHandler) Get(name string) error {
	httputil.SendResponse(h.item, h.w)
	return nil
}
func (h *configServiceTemplateHandler) Post(name string) error {
	h.cfg.ServiceTemplates[name] = h.input.Item
	h.save = h.input.Item
	return nil
}
func (h *configServiceTemplateHandler) Put(name string) error {
	h.cfg.ServiceTemplates[name] = h.input.Item
	h.save = h.input.Item
	return nil
}
func (h *configServiceTemplateHandler) Patch(name string) error {
	proto.Merge(h.item, h.input.Item)
	h.item.Interfaces = h.input.Item.Interfaces
	h.item.ServiceRoles = h.input.Item.ServiceRoles
	h.item.Ui = h.input.Item.Ui
	h.save = h.item
	return nil
}
func (h *configServiceTemplateHandler) Remove(name string) error {
	delete(h.cfg.ServiceTemplates, name)
	h.save = &pb.ServiceTemplate{}
	return nil
}
func (h *configServiceTemplateHandler) CheckIntegrity() *status.Status {
	return h.s.configCheckIntegrity(h.cfg, h.input.Modification, h.r)
}
func (h *configServiceTemplateHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return h.s.saveConfig(h.cfg, desc, typeName, h.r, h.id, h.item, h.save, h.input.Modification, h.tx)
}

//////////////////////////////////////////////////////////////////

func (s *Service) configPersonaFactory() *httputil.HandlerFactory {
	return &httputil.HandlerFactory{
		TypeName:            "configTestPersona",
		PathPrefix:          configTestPersonaPath,
		HasNamedIdentifiers: true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) httputil.HandlerInterface {
			return NewConfigPersonaHandler(s, w, r)
		},
	}
}

type configPersonaHandler struct {
	s     *Service
	w     http.ResponseWriter
	r     *http.Request
	input *pb.ConfigTestPersonaRequest
	item  *cpb.TestPersona
	save  *cpb.TestPersona
	cfg   *pb.DamConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func NewConfigPersonaHandler(s *Service, w http.ResponseWriter, r *http.Request) *configPersonaHandler {
	return &configPersonaHandler{
		s:     s,
		w:     w,
		r:     r,
		input: &pb.ConfigTestPersonaRequest{},
	}
}
func (h *configPersonaHandler) Setup(tx storage.Tx) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, h.r, noScope, h.input)
	h.cfg = cfg
	h.id = id
	h.tx = tx
	return status, err
}
func (h *configPersonaHandler) LookupItem(name string, vars map[string]string) bool {
	item, ok := h.cfg.TestPersonas[name]
	if !ok {
		return false
	}
	h.item = item
	return true
}
func (h *configPersonaHandler) NormalizeInput(name string, vars map[string]string) error {
	if err := httputil.GetRequest(h.input, h.r); err != nil {
		return err
	}
	if h.input.Item == nil {
		h.input.Item = &cpb.TestPersona{}
	}
	if h.input.Item.Passport == nil {
		h.input.Item.Passport = &cpb.Passport{}
	}
	if h.input.Item.Passport.StandardClaims == nil {
		h.input.Item.Passport.StandardClaims = make(map[string]string)
	}
	if h.input.Item.Ui == nil {
		h.input.Item.Ui = make(map[string]string)
	}
	if h.input.Item.Access != nil {
		sort.Strings(h.input.Item.Access)
	}
	return nil
}
func (h *configPersonaHandler) Get(name string) error {
	httputil.SendResponse(h.item, h.w)
	return nil
}
func (h *configPersonaHandler) Post(name string) error {
	h.cfg.TestPersonas[name] = h.input.Item
	h.save = h.input.Item
	return nil
}
func (h *configPersonaHandler) Put(name string) error {
	h.cfg.TestPersonas[name] = h.input.Item
	h.save = h.input.Item
	return nil
}
func (h *configPersonaHandler) Patch(name string) error {
	proto.Merge(h.item, h.input.Item)
	h.item.Passport = h.input.Item.Passport
	h.item.Access = h.input.Item.Access
	h.item.Ui = h.input.Item.Ui
	h.save = h.item
	return nil
}
func (h *configPersonaHandler) Remove(name string) error {
	delete(h.cfg.TestPersonas, name)
	h.save = &cpb.TestPersona{}
	return nil
}
func (h *configPersonaHandler) CheckIntegrity() *status.Status {
	return h.s.configCheckIntegrity(h.cfg, h.input.Modification, h.r)
}
func (h *configPersonaHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return h.s.saveConfig(h.cfg, desc, typeName, h.r, h.id, h.item, h.save, h.input.Modification, h.tx)
}

// ConfigHistory implements the HistoryConfig RPC method.
func (s *Service) ConfigHistory(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		httputil.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	id, status, err := s.getBearerTokenIdentity(cfg, r)
	if err != nil {
		httputil.HandleError(status, err, w)
		return
	}
	if status, err := s.permissions.CheckAdmin(id); err != nil {
		httputil.HandleError(status, err, w)
		return
	}
	h, status, err := storage.GetHistory(s.store, storage.ConfigDatatype, getRealm(r), storage.DefaultUser, storage.DefaultID, r)
	if err != nil {
		httputil.HandleError(status, err, w)
	}
	httputil.SendResponse(h, w)
}

// ConfigHistoryRevision implements the HistoryRevisionConfig RPC method.
func (s *Service) ConfigHistoryRevision(w http.ResponseWriter, r *http.Request) {
	name := getName(r)
	rev, err := strconv.ParseInt(name, 10, 64)
	if err != nil {
		httputil.HandleError(http.StatusBadRequest, fmt.Errorf("invalid history revision: %q (must be a positive integer)", name), w)
		return
	}
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		httputil.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	id, status, err := s.getBearerTokenIdentity(cfg, r)
	if err != nil {
		httputil.HandleError(status, err, w)
		return
	}
	if status, err := s.permissions.CheckAdmin(id); err != nil {
		httputil.HandleError(status, err, w)
		return
	}
	cfg = &pb.DamConfig{}
	if status, err := s.realmReadTx(storage.ConfigDatatype, getRealm(r), storage.DefaultUser, storage.DefaultID, rev, cfg, nil); err != nil {
		httputil.HandleError(status, err, w)
		return
	}
	httputil.SendResponse(cfg, w)
}

// ConfigReset implements the corresponding method in the DAM API.
func (s *Service) ConfigReset(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		httputil.HandleError(http.StatusServiceUnavailable, err, w)
	}
	id, status, err := s.getBearerTokenIdentity(cfg, r)
	if err != nil {
		httputil.HandleError(status, err, w)
		return
	}
	if status, err := s.permissions.CheckAdmin(id); err != nil {
		httputil.HandleError(status, err, w)
		return
	}
	if err = s.store.Wipe(storage.AllRealms); err != nil {
		httputil.HandleError(http.StatusInternalServerError, err, w)
		return
	}
	if err = s.ImportFiles(importDefault); err != nil {
		httputil.HandleError(http.StatusInternalServerError, err, w)
		return
	}

	// Reset clients in Hyrdra
	if s.useHydra {
		conf, err := s.loadConfig(nil, storage.DefaultRealm)
		if err != nil {
			httputil.HandleError(http.StatusServiceUnavailable, err, w)
			return
		}

		secrets, err := s.loadSecrets(nil)
		if err != nil {
			httputil.HandleError(http.StatusServiceUnavailable, err, w)
			return
		}

		if err := s.syncToHydra(conf.Clients, secrets.ClientSecrets, 0); err != nil {
			httputil.HandleError(http.StatusServiceUnavailable, err, w)
			return
		}
	}
}

// ConfigTestPersonas implements the ConfigTestPersonas RPC method.
func (s *Service) ConfigTestPersonas(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		httputil.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}
	id, status, err := s.getBearerTokenIdentity(cfg, r)
	if err != nil {
		httputil.HandleError(status, err, w)
		return
	}
	if status, err := s.permissions.CheckAdmin(id); err != nil {
		httputil.HandleError(status, err, w)
		return
	}
	out := &pb.GetTestPersonasResponse{
		Personas: cfg.TestPersonas,
	}
	httputil.SendResponse(out, w)
}
