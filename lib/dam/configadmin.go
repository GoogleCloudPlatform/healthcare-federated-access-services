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
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/check" /* copybara-comment: check */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/handlerfactory" /* copybara-comment: handlerfactory */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
)

func (s *Service) configFactory() *handlerfactory.Options {
	return &handlerfactory.Options{
		TypeName:            "config",
		PathPrefix:          configPath,
		HasNamedIdentifiers: false,
		Service:             NewConfigHandler(s),
	}
}

type configHandler struct {
	s     *Service
	input *pb.ConfigRequest
	save  *pb.DamConfig
	cfg   *pb.DamConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func NewConfigHandler(s *Service) *configHandler {
	return &configHandler{
		s:     s,
		input: &pb.ConfigRequest{},
	}
}
func (h *configHandler) Setup(r *http.Request, tx storage.Tx) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, r, noScope, h.input)
	h.tx = tx
	h.cfg = cfg
	h.id = id
	return status, err
}
func (h *configHandler) LookupItem(r *http.Request, name string, vars map[string]string) bool {
	// Trival name as there is only one config and it was fetched during Setup().
	return true
}
func (h *configHandler) NormalizeInput(r *http.Request, name string, vars map[string]string) error {
	if err := httputil.DecodeProtoReq(h.input, r); err != nil {
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
func (h *configHandler) Get(r *http.Request, name string) (proto.Message, error) {
	return makeConfig(h.cfg), nil
}
func (h *configHandler) Post(r *http.Request, name string) (proto.Message, error) {
	return nil, fmt.Errorf("POST not allowed")
}
func (h *configHandler) Put(r *http.Request, name string) (proto.Message, error) {
	if h.cfg.Version != h.input.Item.Version {
		// TODO: consider upgrading older config versions automatically.
		return nil, fmt.Errorf("PUT of config version %q mismatched with existing config version %q", h.input.Item.Version, h.cfg.Version)
	}
	h.save = receiveConfig(h.input.Item, h.cfg)
	// Retain the revision number (it will be incremented upon saving).
	h.save.Revision = h.cfg.Revision
	return nil, nil
}
func (h *configHandler) Patch(r *http.Request, name string) (proto.Message, error) {
	return nil, fmt.Errorf("PATCH not allowed")
}
func (h *configHandler) Remove(r *http.Request, name string) (proto.Message, error) {
	return nil, fmt.Errorf("DELETE not allowed")
}
func (h *configHandler) CheckIntegrity(r *http.Request) *status.Status {
	return configCheckIntegrity(h.save, h.input.Modification, r, h.s.ValidateCfgOpts())
}
func (h *configHandler) Save(r *http.Request, tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	if err := h.s.saveConfig(h.save, desc, typeName, r, h.id, h.cfg, h.save, h.input.Modification, tx); err != nil {
		return err
	}
	secrets, err := h.s.loadSecrets(tx)
	if err != nil {
		return err
	}
	// Assumes that secrets don't change within this handler.
	if h.s.useHydra && !check.ClientsEqual(h.cfg.Clients, h.save.Clients) {
		if _, err = h.s.syncToHydra(h.save.Clients, secrets.ClientSecrets, 0, tx); err != nil {
			return err
		}
	}
	if !proto.Equal(h.cfg.Options, h.save.Options) {
		h.s.updateWarehouseOptions(h.save.Options, getRealm(r), h.tx)
		return h.s.registerProject(h.save.Options.GcpServiceAccountProject, h.tx)
	}
	return nil
}

//////////////////////////////////////////////////////////////////

func (s *Service) configOptionsFactory() *handlerfactory.Options {
	return &handlerfactory.Options{
		TypeName:            "configOptions",
		PathPrefix:          configOptionsPath,
		HasNamedIdentifiers: false,
		Service:             NewConfigOptionsHandler(s),
	}
}

type configOptionsHandler struct {
	s     *Service
	input *pb.ConfigOptionsRequest
	item  *pb.ConfigOptions
	orig  *pb.ConfigOptions
	save  *pb.ConfigOptions
	cfg   *pb.DamConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func NewConfigOptionsHandler(s *Service) *configOptionsHandler {
	return &configOptionsHandler{
		s:     s,
		input: &pb.ConfigOptionsRequest{},
	}
}
func (h *configOptionsHandler) Setup(r *http.Request, tx storage.Tx) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, r, noScope, h.input)
	h.cfg = cfg
	h.id = id
	h.tx = tx
	return status, err
}
func (h *configOptionsHandler) LookupItem(r *http.Request, name string, vars map[string]string) bool {
	h.item = h.cfg.Options
	return true
}
func (h *configOptionsHandler) NormalizeInput(r *http.Request, name string, vars map[string]string) error {
	if err := httputil.DecodeProtoReq(h.input, r); err != nil {
		return err
	}
	if h.input.Item == nil {
		h.input.Item = &pb.ConfigOptions{}
	}
	h.input.Item = receiveConfigOptions(h.input.Item, h.cfg)
	return nil
}
func (h *configOptionsHandler) Get(r *http.Request, name string) (proto.Message, error) {
	return makeConfigOptions(h.item), nil
}
func (h *configOptionsHandler) Post(r *http.Request, name string) (proto.Message, error) {
	return nil, fmt.Errorf("POST not allowed")
}
func (h *configOptionsHandler) Put(r *http.Request, name string) (proto.Message, error) {
	h.orig = &pb.ConfigOptions{}
	proto.Merge(h.orig, h.item)
	h.cfg.Options = h.input.Item
	h.save = h.input.Item
	return nil, nil
}
func (h *configOptionsHandler) Patch(r *http.Request, name string) (proto.Message, error) {
	h.orig = &pb.ConfigOptions{}
	proto.Merge(h.orig, h.item)
	proto.Merge(h.item, h.input.Item)
	h.item.ReadOnlyMasterRealm = h.input.Item.ReadOnlyMasterRealm
	h.save = h.item
	return nil, nil
}
func (h *configOptionsHandler) Remove(r *http.Request, name string) (proto.Message, error) {
	return nil, fmt.Errorf("DELETE not allowed")
}
func (h *configOptionsHandler) CheckIntegrity(r *http.Request) *status.Status {
	return configCheckIntegrity(h.cfg, h.input.Modification, r, h.s.ValidateCfgOpts())
}
func (h *configOptionsHandler) Save(r *http.Request, tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	if err := h.s.saveConfig(h.cfg, desc, typeName, r, h.id, h.item, h.save, h.input.Modification, h.tx); err != nil {
		return err
	}
	if h.orig != nil && !proto.Equal(h.orig, h.save) {
		h.s.updateWarehouseOptions(h.save, getRealm(r), h.tx)
		return h.s.registerProject(h.save.GcpServiceAccountProject, h.tx)
	}
	return nil
}

//////////////////////////////////////////////////////////////////

func (s *Service) configResourceFactory() *handlerfactory.Options {
	return &handlerfactory.Options{
		TypeName:            "configResource",
		PathPrefix:          configResourcePath,
		HasNamedIdentifiers: true,
		Service:             NewConfigResourceHandler(s),
	}
}

type configResourceHandler struct {
	s     *Service
	input *pb.ConfigResourceRequest
	item  *pb.Resource
	save  *pb.Resource
	cfg   *pb.DamConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func NewConfigResourceHandler(s *Service) *configResourceHandler {
	return &configResourceHandler{
		s:     s,
		input: &pb.ConfigResourceRequest{},
	}
}
func (h *configResourceHandler) Setup(r *http.Request, tx storage.Tx) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, r, noScope, h.input)
	h.cfg = cfg
	h.id = id
	h.tx = tx
	return status, err
}
func (h *configResourceHandler) LookupItem(r *http.Request, name string, vars map[string]string) bool {
	item, ok := h.cfg.Resources[name]
	if !ok {
		return false
	}
	h.item = item
	return true
}
func (h *configResourceHandler) NormalizeInput(r *http.Request, name string, vars map[string]string) error {
	if err := httputil.DecodeProtoReq(h.input, r); err != nil {
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
func (h *configResourceHandler) Get(r *http.Request, name string) (proto.Message, error) {
	return h.item, nil
}
func (h *configResourceHandler) Post(r *http.Request, name string) (proto.Message, error) {
	h.cfg.Resources[name] = h.input.Item
	h.save = h.input.Item
	return nil, nil
}
func (h *configResourceHandler) Put(r *http.Request, name string) (proto.Message, error) {
	h.cfg.Resources[name] = h.input.Item
	h.save = h.input.Item
	return nil, nil
}
func (h *configResourceHandler) Patch(r *http.Request, name string) (proto.Message, error) {
	proto.Merge(h.item, h.input.Item)
	h.item.Views = h.input.Item.Views
	h.item.Ui = h.input.Item.Ui
	h.save = h.item
	return nil, nil
}
func (h *configResourceHandler) Remove(r *http.Request, name string) (proto.Message, error) {
	rmTestResource(h.cfg, name)
	delete(h.cfg.Resources, name)
	h.save = &pb.Resource{}
	return nil, nil
}
func (h *configResourceHandler) CheckIntegrity(r *http.Request) *status.Status {
	return configCheckIntegrity(h.cfg, h.input.Modification, r, h.s.ValidateCfgOpts())
}
func (h *configResourceHandler) Save(r *http.Request, tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return h.s.saveConfig(h.cfg, desc, typeName, r, h.id, h.item, h.save, h.input.Modification, h.tx)
}

//////////////////////////////////////////////////////////////////

func (s *Service) configViewFactory() *handlerfactory.Options {
	return &handlerfactory.Options{
		TypeName:            "configView",
		PathPrefix:          configViewPath,
		HasNamedIdentifiers: true,
		Service:             NewConfigViewHandler(s),
	}
}

type configViewHandler struct {
	s       *Service
	input   *pb.ConfigViewRequest
	item    *pb.View
	save    *pb.View
	res     *pb.Resource
	resName string
	cfg     *pb.DamConfig
	id      *ga4gh.Identity
	tx      storage.Tx
}

func NewConfigViewHandler(s *Service) *configViewHandler {
	return &configViewHandler{
		s:     s,
		input: &pb.ConfigViewRequest{},
	}
}
func (h *configViewHandler) Setup(r *http.Request, tx storage.Tx) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, r, noScope, h.input)
	h.cfg = cfg
	h.id = id
	h.tx = tx
	return status, err
}
func (h *configViewHandler) LookupItem(r *http.Request, name string, vars map[string]string) bool {
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
func (h *configViewHandler) NormalizeInput(r *http.Request, name string, vars map[string]string) error {
	if err := httputil.DecodeProtoReq(h.input, r); err != nil {
		return err
	}
	if h.input.Item == nil {
		h.input.Item = &pb.View{}
	}
	h.input.Item = receiveView(h.input.Item)
	return nil
}
func (h *configViewHandler) Get(r *http.Request, name string) (proto.Message, error) {
	return h.item, nil
}
func (h *configViewHandler) Post(r *http.Request, name string) (proto.Message, error) {
	h.cfg.Resources[h.resName].Views[name] = h.input.Item
	h.save = h.input.Item
	return nil, nil
}
func (h *configViewHandler) Put(r *http.Request, name string) (proto.Message, error) {
	h.cfg.Resources[h.resName].Views[name] = h.input.Item
	h.save = h.input.Item
	return nil, nil
}
func (h *configViewHandler) Patch(r *http.Request, name string) (proto.Message, error) {
	proto.Merge(h.item, h.input.Item)
	h.item.Items = h.input.Item.Items
	h.item.Labels = h.input.Item.Labels
	h.item.Roles = h.input.Item.Roles
	h.item.Ui = h.input.Item.Ui
	h.save = h.item
	return nil, nil
}
func (h *configViewHandler) Remove(r *http.Request, name string) (proto.Message, error) {
	rmTestView(h.cfg, h.resName, name)
	delete(h.cfg.Resources[h.resName].Views, name)
	h.save = &pb.View{}
	return nil, nil
}
func (h *configViewHandler) CheckIntegrity(r *http.Request) *status.Status {
	return configCheckIntegrity(h.cfg, h.input.Modification, r, h.s.ValidateCfgOpts())
}
func (h *configViewHandler) Save(r *http.Request, tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return h.s.saveConfig(h.cfg, desc, typeName, r, h.id, h.item, h.save, h.input.Modification, h.tx)
}

//////////////////////////////////////////////////////////////////

func (s *Service) configIssuerFactory() *handlerfactory.Options {
	return &handlerfactory.Options{
		TypeName:            "configTrustedIssuer",
		PathPrefix:          configTrustedIssuerPath,
		HasNamedIdentifiers: true,
		Service:             NewConfigIssuerHandler(s),
	}
}

type configIssuerHandler struct {
	s     *Service
	input *pb.ConfigTrustedIssuerRequest
	item  *pb.TrustedIssuer
	save  *pb.TrustedIssuer
	cfg   *pb.DamConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func NewConfigIssuerHandler(s *Service) *configIssuerHandler {
	return &configIssuerHandler{
		s:     s,
		input: &pb.ConfigTrustedIssuerRequest{},
	}
}
func (h *configIssuerHandler) Setup(r *http.Request, tx storage.Tx) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, r, noScope, h.input)
	h.cfg = cfg
	h.id = id
	h.tx = tx
	return status, err
}
func (h *configIssuerHandler) LookupItem(r *http.Request, name string, vars map[string]string) bool {
	item, ok := h.cfg.TrustedIssuers[name]
	if !ok {
		return false
	}
	h.item = item
	return true
}
func (h *configIssuerHandler) NormalizeInput(r *http.Request, name string, vars map[string]string) error {
	if err := httputil.DecodeProtoReq(h.input, r); err != nil {
		return err
	}
	if h.input.Item == nil {
		h.input.Item = &pb.TrustedIssuer{}
	}
	if h.input.Item.Ui == nil {
		h.input.Item.Ui = make(map[string]string)
	}
	return nil
}
func (h *configIssuerHandler) Get(r *http.Request, name string) (proto.Message, error) {
	return h.item, nil
}
func (h *configIssuerHandler) Post(r *http.Request, name string) (proto.Message, error) {
	h.cfg.TrustedIssuers[name] = h.input.Item
	h.save = h.input.Item
	return nil, nil
}
func (h *configIssuerHandler) Put(r *http.Request, name string) (proto.Message, error) {
	h.cfg.TrustedIssuers[name] = h.input.Item
	h.save = h.input.Item
	return nil, nil
}
func (h *configIssuerHandler) Patch(r *http.Request, name string) (proto.Message, error) {
	proto.Merge(h.item, h.input.Item)
	h.item.Ui = h.input.Item.Ui
	h.save = h.item
	return nil, nil
}
func (h *configIssuerHandler) Remove(r *http.Request, name string) (proto.Message, error) {
	delete(h.cfg.TrustedIssuers, name)
	h.save = &pb.TrustedIssuer{}
	return nil, nil
}
func (h *configIssuerHandler) CheckIntegrity(r *http.Request) *status.Status {
	return configCheckIntegrity(h.cfg, h.input.Modification, r, h.s.ValidateCfgOpts())
}
func (h *configIssuerHandler) Save(r *http.Request, tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return h.s.saveConfig(h.cfg, desc, typeName, r, h.id, h.item, h.save, h.input.Modification, h.tx)
}

//////////////////////////////////////////////////////////////////

func (s *Service) configSourceFactory() *handlerfactory.Options {
	return &handlerfactory.Options{
		TypeName:            "configTrustedSource",
		PathPrefix:          configTrustedSourcePath,
		HasNamedIdentifiers: true,
		Service:             NewConfigSourceHandler(s),
	}
}

type configSourceHandler struct {
	s     *Service
	input *pb.ConfigTrustedSourceRequest
	item  *pb.TrustedSource
	save  *pb.TrustedSource
	cfg   *pb.DamConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func NewConfigSourceHandler(s *Service) *configSourceHandler {
	return &configSourceHandler{
		s:     s,
		input: &pb.ConfigTrustedSourceRequest{},
	}
}
func (h *configSourceHandler) Setup(r *http.Request, tx storage.Tx) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, r, noScope, h.input)
	h.cfg = cfg
	h.id = id
	h.tx = tx
	return status, err
}
func (h *configSourceHandler) LookupItem(r *http.Request, name string, vars map[string]string) bool {
	item, ok := h.cfg.TrustedSources[name]
	if !ok {
		return false
	}
	h.item = item
	return true
}
func (h *configSourceHandler) NormalizeInput(r *http.Request, name string, vars map[string]string) error {
	if err := httputil.DecodeProtoReq(h.input, r); err != nil {
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
func (h *configSourceHandler) Get(r *http.Request, name string) (proto.Message, error) {
	return h.item, nil
}
func (h *configSourceHandler) Post(r *http.Request, name string) (proto.Message, error) {
	h.cfg.TrustedSources[name] = h.input.Item
	h.save = h.input.Item
	return nil, nil
}
func (h *configSourceHandler) Put(r *http.Request, name string) (proto.Message, error) {
	h.cfg.TrustedSources[name] = h.input.Item
	h.save = h.input.Item
	return nil, nil
}
func (h *configSourceHandler) Patch(r *http.Request, name string) (proto.Message, error) {
	proto.Merge(h.item, h.input.Item)
	h.item.Sources = h.input.Item.Sources
	h.item.VisaTypes = h.input.Item.VisaTypes
	h.item.Ui = h.input.Item.Ui
	h.save = h.item
	return nil, nil
}
func (h *configSourceHandler) Remove(r *http.Request, name string) (proto.Message, error) {
	delete(h.cfg.TrustedSources, name)
	h.save = &pb.TrustedSource{}
	return nil, nil
}
func (h *configSourceHandler) CheckIntegrity(r *http.Request) *status.Status {
	return configCheckIntegrity(h.cfg, h.input.Modification, r, h.s.ValidateCfgOpts())
}
func (h *configSourceHandler) Save(r *http.Request, tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return h.s.saveConfig(h.cfg, desc, typeName, r, h.id, h.item, h.save, h.input.Modification, h.tx)
}

//////////////////////////////////////////////////////////////////

func (s *Service) configPolicyFactory() *handlerfactory.Options {
	return &handlerfactory.Options{
		TypeName:            "configPolicy",
		PathPrefix:          configPolicyPath,
		HasNamedIdentifiers: true,
		Service:             NewConfigPolicyHandler(s),
	}
}

type configPolicyHandler struct {
	s     *Service
	input *pb.ConfigPolicyRequest
	item  *pb.Policy
	save  *pb.Policy
	cfg   *pb.DamConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func NewConfigPolicyHandler(s *Service) *configPolicyHandler {
	return &configPolicyHandler{
		s:     s,
		input: &pb.ConfigPolicyRequest{},
	}
}
func (h *configPolicyHandler) Setup(r *http.Request, tx storage.Tx) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, r, noScope, h.input)
	h.cfg = cfg
	h.id = id
	h.tx = tx
	return status, err
}
func (h *configPolicyHandler) LookupItem(r *http.Request, name string, vars map[string]string) bool {
	item, ok := h.cfg.Policies[name]
	if !ok {
		return false
	}
	h.item = item
	return true
}
func (h *configPolicyHandler) NormalizeInput(r *http.Request, name string, vars map[string]string) error {
	if err := httputil.DecodeProtoReq(h.input, r); err != nil {
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
func (h *configPolicyHandler) Get(r *http.Request, name string) (proto.Message, error) {
	return h.item, nil
}
func (h *configPolicyHandler) Post(r *http.Request, name string) (proto.Message, error) {
	h.cfg.Policies[name] = h.input.Item
	h.save = h.input.Item
	return nil, nil
}
func (h *configPolicyHandler) Put(r *http.Request, name string) (proto.Message, error) {
	h.cfg.Policies[name] = h.input.Item
	h.save = h.input.Item
	return nil, nil
}
func (h *configPolicyHandler) Patch(r *http.Request, name string) (proto.Message, error) {
	proto.Merge(h.item, h.input.Item)
	h.item.AnyOf = h.input.Item.AnyOf
	h.item.Ui = h.input.Item.Ui
	h.save = h.item
	return nil, nil
}
func (h *configPolicyHandler) Remove(r *http.Request, name string) (proto.Message, error) {
	delete(h.cfg.Policies, name)
	h.save = &pb.Policy{}
	return nil, nil
}
func (h *configPolicyHandler) CheckIntegrity(r *http.Request) *status.Status {
	return configCheckIntegrity(h.cfg, h.input.Modification, r, h.s.ValidateCfgOpts())
}
func (h *configPolicyHandler) Save(r *http.Request, tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return h.s.saveConfig(h.cfg, desc, typeName, r, h.id, h.item, h.save, h.input.Modification, h.tx)
}

//////////////////////////////////////////////////////////////////

func (s *Service) configVisaTypeFactory() *handlerfactory.Options {
	return &handlerfactory.Options{
		TypeName:            "configVisaType",
		PathPrefix:          configClaimDefPath,
		HasNamedIdentifiers: true,
		Service:             NewConfigVisaTypeHandler(s),
	}
}

type configVisaTypeHandler struct {
	s     *Service
	input *pb.ConfigVisaTypeRequest
	item  *pb.VisaType
	save  *pb.VisaType
	cfg   *pb.DamConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func NewConfigVisaTypeHandler(s *Service) *configVisaTypeHandler {
	return &configVisaTypeHandler{
		s:     s,
		input: &pb.ConfigVisaTypeRequest{},
	}
}
func (h *configVisaTypeHandler) Setup(r *http.Request, tx storage.Tx) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, r, noScope, h.input)
	h.cfg = cfg
	h.id = id
	h.tx = tx
	return status, err
}
func (h *configVisaTypeHandler) LookupItem(r *http.Request, name string, vars map[string]string) bool {
	item, ok := h.cfg.VisaTypes[name]
	if !ok {
		return false
	}
	h.item = item
	return true
}
func (h *configVisaTypeHandler) NormalizeInput(r *http.Request, name string, vars map[string]string) error {
	if err := httputil.DecodeProtoReq(h.input, r); err != nil {
		return err
	}
	if h.input.Item == nil {
		h.input.Item = &pb.VisaType{}
	}
	if h.input.Item.Ui == nil {
		h.input.Item.Ui = make(map[string]string)
	}
	return nil
}
func (h *configVisaTypeHandler) Get(r *http.Request, name string) (proto.Message, error) {
	return h.item, nil
}
func (h *configVisaTypeHandler) Post(r *http.Request, name string) (proto.Message, error) {
	h.cfg.VisaTypes[name] = h.input.Item
	h.save = h.input.Item
	return nil, nil
}
func (h *configVisaTypeHandler) Put(r *http.Request, name string) (proto.Message, error) {
	h.cfg.VisaTypes[name] = h.input.Item
	h.save = h.input.Item
	return nil, nil
}
func (h *configVisaTypeHandler) Patch(r *http.Request, name string) (proto.Message, error) {
	proto.Merge(h.item, h.input.Item)
	h.item.Ui = h.input.Item.Ui
	h.save = h.item
	return nil, nil
}
func (h *configVisaTypeHandler) Remove(r *http.Request, name string) (proto.Message, error) {
	delete(h.cfg.VisaTypes, name)
	h.save = &pb.VisaType{}
	return nil, nil
}
func (h *configVisaTypeHandler) CheckIntegrity(r *http.Request) *status.Status {
	return configCheckIntegrity(h.cfg, h.input.Modification, r, h.s.ValidateCfgOpts())
}
func (h *configVisaTypeHandler) Save(r *http.Request, tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return h.s.saveConfig(h.cfg, desc, typeName, r, h.id, h.item, h.save, h.input.Modification, h.tx)
}

//////////////////////////////////////////////////////////////////

func (s *Service) configServiceTemplateFactory() *handlerfactory.Options {
	return &handlerfactory.Options{
		TypeName:            "configServiceTemplate",
		PathPrefix:          configServiceTemplatePath,
		HasNamedIdentifiers: true,
		Service:             NewConfigServiceTemplateHandler(s),
	}
}

type configServiceTemplateHandler struct {
	s     *Service
	input *pb.ConfigServiceTemplateRequest
	item  *pb.ServiceTemplate
	save  *pb.ServiceTemplate
	cfg   *pb.DamConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func NewConfigServiceTemplateHandler(s *Service) *configServiceTemplateHandler {
	return &configServiceTemplateHandler{
		s:     s,
		input: &pb.ConfigServiceTemplateRequest{},
	}
}
func (h *configServiceTemplateHandler) Setup(r *http.Request, tx storage.Tx) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, r, noScope, h.input)
	h.cfg = cfg
	h.id = id
	h.tx = tx
	return status, err
}
func (h *configServiceTemplateHandler) LookupItem(r *http.Request, name string, vars map[string]string) bool {
	item, ok := h.cfg.ServiceTemplates[name]
	if !ok {
		return false
	}
	h.item = item
	return true
}
func (h *configServiceTemplateHandler) NormalizeInput(r *http.Request, name string, vars map[string]string) error {
	if err := httputil.DecodeProtoReq(h.input, r); err != nil {
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
func (h *configServiceTemplateHandler) Get(r *http.Request, name string) (proto.Message, error) {
	return h.item, nil
}
func (h *configServiceTemplateHandler) Post(r *http.Request, name string) (proto.Message, error) {
	h.cfg.ServiceTemplates[name] = h.input.Item
	h.save = h.input.Item
	return nil, nil
}
func (h *configServiceTemplateHandler) Put(r *http.Request, name string) (proto.Message, error) {
	h.cfg.ServiceTemplates[name] = h.input.Item
	h.save = h.input.Item
	return nil, nil
}
func (h *configServiceTemplateHandler) Patch(r *http.Request, name string) (proto.Message, error) {
	proto.Merge(h.item, h.input.Item)
	h.item.Interfaces = h.input.Item.Interfaces
	h.item.ServiceRoles = h.input.Item.ServiceRoles
	h.item.Ui = h.input.Item.Ui
	h.save = h.item
	return nil, nil
}
func (h *configServiceTemplateHandler) Remove(r *http.Request, name string) (proto.Message, error) {
	delete(h.cfg.ServiceTemplates, name)
	h.save = &pb.ServiceTemplate{}
	return nil, nil
}
func (h *configServiceTemplateHandler) CheckIntegrity(r *http.Request) *status.Status {
	return configCheckIntegrity(h.cfg, h.input.Modification, r, h.s.ValidateCfgOpts())
}
func (h *configServiceTemplateHandler) Save(r *http.Request, tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return h.s.saveConfig(h.cfg, desc, typeName, r, h.id, h.item, h.save, h.input.Modification, h.tx)
}

//////////////////////////////////////////////////////////////////

func (s *Service) configPersonaFactory() *handlerfactory.Options {
	return &handlerfactory.Options{
		TypeName:            "configTestPersona",
		PathPrefix:          configTestPersonaPath,
		HasNamedIdentifiers: true,
		Service:             NewConfigPersonaHandler(s),
	}
}

type configPersonaHandler struct {
	s     *Service
	input *pb.ConfigTestPersonaRequest
	item  *cpb.TestPersona
	save  *cpb.TestPersona
	cfg   *pb.DamConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func NewConfigPersonaHandler(s *Service) *configPersonaHandler {
	return &configPersonaHandler{
		s:     s,
		input: &pb.ConfigTestPersonaRequest{},
	}
}
func (h *configPersonaHandler) Setup(r *http.Request, tx storage.Tx) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, r, noScope, h.input)
	h.cfg = cfg
	h.id = id
	h.tx = tx
	return status, err
}
func (h *configPersonaHandler) LookupItem(r *http.Request, name string, vars map[string]string) bool {
	item, ok := h.cfg.TestPersonas[name]
	if !ok {
		return false
	}
	h.item = item
	return true
}
func (h *configPersonaHandler) NormalizeInput(r *http.Request, name string, vars map[string]string) error {
	if err := httputil.DecodeProtoReq(h.input, r); err != nil {
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
func (h *configPersonaHandler) Get(r *http.Request, name string) (proto.Message, error) {
	return h.item, nil
}
func (h *configPersonaHandler) Post(r *http.Request, name string) (proto.Message, error) {
	h.cfg.TestPersonas[name] = h.input.Item
	h.save = h.input.Item
	return nil, nil
}
func (h *configPersonaHandler) Put(r *http.Request, name string) (proto.Message, error) {
	h.cfg.TestPersonas[name] = h.input.Item
	h.save = h.input.Item
	return nil, nil
}
func (h *configPersonaHandler) Patch(r *http.Request, name string) (proto.Message, error) {
	proto.Merge(h.item, h.input.Item)
	h.item.Passport = h.input.Item.Passport
	h.item.Access = h.input.Item.Access
	h.item.Ui = h.input.Item.Ui
	h.save = h.item
	return nil, nil
}
func (h *configPersonaHandler) Remove(r *http.Request, name string) (proto.Message, error) {
	delete(h.cfg.TestPersonas, name)
	h.save = &cpb.TestPersona{}
	return nil, nil
}
func (h *configPersonaHandler) CheckIntegrity(r *http.Request) *status.Status {
	return configCheckIntegrity(h.cfg, h.input.Modification, r, h.s.ValidateCfgOpts())
}
func (h *configPersonaHandler) Save(r *http.Request, tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return h.s.saveConfig(h.cfg, desc, typeName, r, h.id, h.item, h.save, h.input.Modification, h.tx)
}

////////////////////////////////////////////////////////////

// ConfigHistory implements the HistoryConfig RPC method.
func (s *Service) ConfigHistory(w http.ResponseWriter, r *http.Request) {
	h, sts, err := storage.GetHistory(s.store, storage.ConfigDatatype, getRealm(r), storage.DefaultUser, storage.DefaultID, r)
	if err != nil {
		httputil.WriteError(w, status.Errorf(httputil.RPCCode(sts), "%v", err))
	}
	httputil.WriteResp(w, h)
}

// ConfigHistoryRevision implements the HistoryRevisionConfig RPC method.
func (s *Service) ConfigHistoryRevision(w http.ResponseWriter, r *http.Request) {
	name := getName(r)
	rev, err := strconv.ParseInt(name, 10, 64)
	if err != nil {
		httputil.WriteError(w, status.Errorf(codes.InvalidArgument, "invalid history revision: %q (must be a positive integer)", name))
		return
	}
	cfg := &pb.DamConfig{}
	if sts, err := s.realmReadTx(storage.ConfigDatatype, getRealm(r), storage.DefaultUser, storage.DefaultID, rev, cfg, nil); err != nil {
		httputil.WriteError(w, status.Errorf(httputil.RPCCode(sts), "%v", err))
		return
	}
	httputil.WriteResp(w, cfg)
}

// ConfigReset implements the corresponding method in the DAM API.
func (s *Service) ConfigReset(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Wipe(storage.AllRealms); err != nil {
		httputil.WriteError(w, status.Errorf(codes.Internal, "%v", err))
		return
	}
	if err := ImportConfig(s.store, s.serviceName, s.warehouse, nil); err != nil {
		httputil.WriteError(w, status.Errorf(codes.Internal, "%v", err))
		return
	}

	// Reset clients in Hyrdra
	if s.useHydra {
		conf, err := s.loadConfig(nil, storage.DefaultRealm)
		if err != nil {
			httputil.WriteError(w, status.Errorf(codes.Unavailable, "%v", err))
			return
		}

		secrets, err := s.loadSecrets(nil)
		if err != nil {
			httputil.WriteError(w, status.Errorf(codes.Unavailable, "%v", err))
			return
		}

		if _, err := s.syncToHydra(conf.Clients, secrets.ClientSecrets, 0, nil); err != nil {
			httputil.WriteError(w, status.Errorf(codes.Unavailable, "%v", err))
			return
		}
	}
}

// ConfigTestPersonas implements the ConfigTestPersonas RPC method.
func (s *Service) ConfigTestPersonas(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.loadConfig(nil, getRealm(r))
	if err != nil {
		httputil.WriteError(w, status.Errorf(codes.Unavailable, "%v", err))
		return
	}
	out := &pb.GetTestPersonasResponse{
		Personas: cfg.TestPersonas,
	}
	httputil.WriteResp(w, out)
}
