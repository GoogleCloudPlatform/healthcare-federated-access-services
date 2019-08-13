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
	"reflect"

	"github.com/golang/protobuf/proto"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/adapter"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/common"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/gcp"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/storage"

	ga4gh "github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh"
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1"
	compb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/models"
)

/////////////////////////////////////////////////////////

type realmHandler struct {
	s     *Service
	w     http.ResponseWriter
	r     *http.Request
	input *pb.RealmRequest
	item  *pb.Realm
	cfg   *pb.DamConfig
	id    *ga4gh.Identity
}

func NewRealmHandler(s *Service, w http.ResponseWriter, r *http.Request) *realmHandler {
	return &realmHandler{
		s:     s,
		w:     w,
		r:     r,
		input: &pb.RealmRequest{},
	}
}
func (h *realmHandler) Setup(tx storage.Tx, isAdmin bool) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, isAdmin, h.r, noScope, h.input)
	h.cfg = cfg
	h.id = id
	return status, err
}
func (h *realmHandler) LookupItem(name string, vars map[string]string) bool {
	// Accept any name that passes the name check.
	h.item = &pb.Realm{}
	return true
}
func (h *realmHandler) NormalizeInput(name string, vars map[string]string) error {
	if err := common.GetRequest(h.input, h.r); err != nil {
		return err
	}
	if h.input.Item == nil {
		h.input.Item = &pb.Realm{}
	}
	return nil
}
func (h *realmHandler) Get(name string) error {
	if h.item != nil {
		common.SendResponse(h.item, h.w)
	}
	return nil
}
func (h *realmHandler) Post(name string) error {
	// Accept, but do nothing.
	return nil
}
func (h *realmHandler) Put(name string) error {
	// Accept, but do nothing.
	return nil
}
func (h *realmHandler) Patch(name string) error {
	// Accept, but do nothing.
	return nil
}
func (h *realmHandler) Remove(name string) error {
	if err := h.s.store.Wipe(name); err != nil {
		return err
	}
	if name == storage.DefaultRealm {
		return h.s.importFiles()
	}
	return h.s.unregisterRealm(h.cfg, name)
}
func (h *realmHandler) CheckIntegrity() (proto.Message, int, error) {
	return nil, http.StatusOK, nil
}
func (h *realmHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	// Accept, but do nothing.
	return nil
}

/////////////////////////////////////////////////////////

type processesHandler struct {
	s     *Service
	w     http.ResponseWriter
	r     *http.Request
	input *pb.BackgroundProcessesRequest
	item  map[string]*pb.BackgroundProcess
	cfg   *pb.DamConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func NewProcessesHandler(s *Service, w http.ResponseWriter, r *http.Request) *processesHandler {
	return &processesHandler{
		s:     s,
		w:     w,
		r:     r,
		input: &pb.BackgroundProcessesRequest{},
	}
}
func (h *processesHandler) Setup(tx storage.Tx, isAdmin bool) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, isAdmin, h.r, noScope, h.input)
	h.tx = tx
	h.cfg = cfg
	h.id = id
	return status, err
}
func (h *processesHandler) LookupItem(name string, vars map[string]string) bool {
	h.item = make(map[string]*pb.BackgroundProcess)
	m := make(map[string]map[string]proto.Message)
	err := h.s.store.MultiReadTx(gcp.BackgroundProcessDataType, storage.DefaultRealm, storage.DefaultUser, m, &pb.BackgroundProcess{}, h.tx)
	if err != nil {
		return false
	}
	for _, userVal := range m {
		for k, v := range userVal {
			if process, ok := v.(*pb.BackgroundProcess); ok {
				h.item[k] = process
			}
		}
	}
	return true
}
func (h *processesHandler) NormalizeInput(name string, vars map[string]string) error {
	if err := common.GetRequest(h.input, h.r); err != nil {
		return err
	}
	return nil
}
func (h *processesHandler) Get(name string) error {
	if h.item != nil {
		common.SendResponse(&pb.BackgroundProcessesResponse{
			Processes: h.item,
		}, h.w)
	}
	return nil
}
func (h *processesHandler) Post(name string) error {
	return fmt.Errorf("POST not allowed")
}
func (h *processesHandler) Put(name string) error {
	return fmt.Errorf("PUT not allowed")
}
func (h *processesHandler) Patch(name string) error {
	return fmt.Errorf("PATCH not allowed")
}
func (h *processesHandler) Remove(name string) error {
	return fmt.Errorf("DELETE not allowed")
}
func (h *processesHandler) CheckIntegrity() (proto.Message, int, error) {
	return nil, http.StatusOK, nil
}
func (h *processesHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return fmt.Errorf("save not allowed")
}

/////////////////////////////////////////////////////////

type processHandler struct {
	s     *Service
	w     http.ResponseWriter
	r     *http.Request
	input *pb.BackgroundProcessRequest
	item  *pb.BackgroundProcess
	cfg   *pb.DamConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func NewProcessHandler(s *Service, w http.ResponseWriter, r *http.Request) *processHandler {
	return &processHandler{
		s:     s,
		w:     w,
		r:     r,
		input: &pb.BackgroundProcessRequest{},
	}
}
func (h *processHandler) Setup(tx storage.Tx, isAdmin bool) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, isAdmin, h.r, noScope, h.input)
	h.tx = tx
	h.cfg = cfg
	h.id = id
	return status, err
}
func (h *processHandler) LookupItem(name string, vars map[string]string) bool {
	h.item = &pb.BackgroundProcess{}
	err := h.s.store.ReadTx(gcp.BackgroundProcessDataType, storage.DefaultRealm, storage.DefaultUser, name, storage.LatestRev, h.item, h.tx)
	if err != nil {
		return false
	}
	return true
}
func (h *processHandler) NormalizeInput(name string, vars map[string]string) error {
	if err := common.GetRequest(h.input, h.r); err != nil {
		return err
	}
	return nil
}
func (h *processHandler) Get(name string) error {
	if h.item != nil {
		common.SendResponse(&pb.BackgroundProcessResponse{
			Process: h.item,
		}, h.w)
	}
	return nil
}
func (h *processHandler) Post(name string) error {
	return fmt.Errorf("POST not allowed")
}
func (h *processHandler) Put(name string) error {
	return fmt.Errorf("PUT not allowed")
}
func (h *processHandler) Patch(name string) error {
	return fmt.Errorf("PATCH not allowed")
}
func (h *processHandler) Remove(name string) error {
	return fmt.Errorf("DELETE not allowed")
}
func (h *processHandler) CheckIntegrity() (proto.Message, int, error) {
	return nil, http.StatusOK, nil
}
func (h *processHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return fmt.Errorf("save not allowed")
}

/////////////////////////////////////////////////////////

type tokensHandler struct {
	s     *Service
	w     http.ResponseWriter
	r     *http.Request
	input *pb.TokensRequest
	item  []*compb.TokenMetadata
	cfg   *pb.DamConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func NewTokensHandler(s *Service, w http.ResponseWriter, r *http.Request) *tokensHandler {
	return &tokensHandler{
		s:     s,
		w:     w,
		r:     r,
		input: &pb.TokensRequest{},
	}
}
func (h *tokensHandler) Setup(tx storage.Tx, isAdmin bool) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, isAdmin, h.r, noScope, h.input)
	h.tx = tx
	h.cfg = cfg
	h.id = id
	return status, err
}
func (h *tokensHandler) LookupItem(name string, vars map[string]string) bool {
	items, err := h.s.warehouse.ListTokenMetadata(context.Background(), h.cfg.Options.GcpServiceAccountProject, common.TokenUserID(h.id, adapter.SawMaxUserIDLength))
	if err != nil {
		return false
	}
	h.item = items
	return true
}
func (h *tokensHandler) NormalizeInput(name string, vars map[string]string) error {
	return common.GetRequest(h.input, h.r)
}
func (h *tokensHandler) Get(name string) error {
	if h.item != nil {
		common.SendResponse(&pb.TokensResponse{
			Tokens: h.item,
		}, h.w)
	}
	return nil
}
func (h *tokensHandler) Post(name string) error {
	return fmt.Errorf("POST not allowed")
}
func (h *tokensHandler) Put(name string) error {
	return fmt.Errorf("PUT not allowed")
}
func (h *tokensHandler) Patch(name string) error {
	return fmt.Errorf("PATCH not allowed")
}
func (h *tokensHandler) Remove(name string) error {
	if len(h.item) == 0 {
		return nil
	}
	return h.s.warehouse.DeleteTokens(context.Background(), h.cfg.Options.GcpServiceAccountProject, common.TokenUserID(h.id, adapter.SawMaxUserIDLength), nil)
}
func (h *tokensHandler) CheckIntegrity() (proto.Message, int, error) {
	return nil, http.StatusOK, nil
}
func (h *tokensHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return nil
}

/////////////////////////////////////////////////////////

type tokenHandler struct {
	s     *Service
	w     http.ResponseWriter
	r     *http.Request
	input *pb.TokenRequest
	item  *compb.TokenMetadata
	cfg   *pb.DamConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

// NewTokenHandler is the handler for the tokens/{name} endpoint.
func NewTokenHandler(s *Service, w http.ResponseWriter, r *http.Request) *tokenHandler {
	return &tokenHandler{
		s:     s,
		w:     w,
		r:     r,
		input: &pb.TokenRequest{},
	}
}
func (h *tokenHandler) Setup(tx storage.Tx, isAdmin bool) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, isAdmin, h.r, noScope, h.input)
	h.tx = tx
	h.cfg = cfg
	h.id = id
	return status, err
}
func (h *tokenHandler) LookupItem(name string, vars map[string]string) bool {
	item, err := h.s.warehouse.GetTokenMetadata(context.Background(), h.cfg.Options.GcpServiceAccountProject, common.TokenUserID(h.id, adapter.SawMaxUserIDLength), name)
	if err != nil {
		return false
	}
	h.item = item
	return true
}
func (h *tokenHandler) NormalizeInput(name string, vars map[string]string) error {
	return common.GetRequest(h.input, h.r)
}
func (h *tokenHandler) Get(name string) error {
	common.SendResponse(&pb.TokenResponse{
		Token: h.item,
	}, h.w)
	return nil
}
func (h *tokenHandler) Post(name string) error {
	return fmt.Errorf("POST not allowed")
}
func (h *tokenHandler) Put(name string) error {
	return fmt.Errorf("PUT not allowed")
}
func (h *tokenHandler) Patch(name string) error {
	return fmt.Errorf("PATCH not allowed")
}
func (h *tokenHandler) Remove(name string) error {
	list := []string{name}
	return h.s.warehouse.DeleteTokens(context.Background(), h.cfg.Options.GcpServiceAccountProject, common.TokenUserID(h.id, adapter.SawMaxUserIDLength), list)
}
func (h *tokenHandler) CheckIntegrity() (proto.Message, int, error) {
	return nil, http.StatusOK, nil
}
func (h *tokenHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return nil
}

/////////////////////////////////////////////////////////

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
func (h *configHandler) Setup(tx storage.Tx, isAdmin bool) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, isAdmin, h.r, noScope, h.input)
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
	if err := common.GetRequest(h.input, h.r); err != nil {
		return err
	}
	if h.input.Item == nil {
		h.input.Item = &pb.DamConfig{}
	}
	if h.input.Modification == nil {
		h.input.Modification = &pb.ConfigModification{}
	}
	if h.input.Item.Clients == nil {
		h.input.Item.Clients = make(map[string]*pb.Client)
	}
	if h.input.Item.Options == nil {
		h.input.Item.Options = &pb.ConfigOptions{}
	}
	h.input.Item.Options = receiveConfigOptions(h.input.Item.Options, h.cfg)
	return nil
}
func (h *configHandler) Get(name string) error {
	common.SendResponse(makeConfig(h.cfg), h.w)
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
func (h *configHandler) CheckIntegrity() (proto.Message, int, error) {
	return h.s.configCheckIntegrity(h.save, h.input.Modification, h.r)
}
func (h *configHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	if err := h.s.saveConfig(h.save, desc, typeName, h.r, h.id, h.cfg, h.save, h.input.Modification, tx); err != nil {
		return err
	}
	if !reflect.DeepEqual(h.cfg.Options, h.save.Options) {
		return h.s.registerProject(h.save, getRealm(h.r))
	}
	return nil
}

//////////////////////////////////////////////////////////////////

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
func (h *configOptionsHandler) Setup(tx storage.Tx, isAdmin bool) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, isAdmin, h.r, noScope, h.input)
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
	if err := common.GetRequest(h.input, h.r); err != nil {
		return err
	}
	if h.input.Item == nil {
		h.input.Item = &pb.ConfigOptions{}
	}
	h.input.Item = receiveConfigOptions(h.input.Item, h.cfg)
	return nil
}
func (h *configOptionsHandler) Get(name string) error {
	common.SendResponse(makeConfigOptions(h.item), h.w)
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
func (h *configOptionsHandler) CheckIntegrity() (proto.Message, int, error) {
	return h.s.configCheckIntegrity(h.cfg, h.input.Modification, h.r)
}
func (h *configOptionsHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	if err := h.s.saveConfig(h.cfg, desc, typeName, h.r, h.id, h.item, h.save, h.input.Modification, h.tx); err != nil {
		return err
	}
	if h.orig != nil && !reflect.DeepEqual(h.orig, h.save) {
		return h.s.registerProject(h.cfg, getRealm(h.r))
	}
	return nil
}

//////////////////////////////////////////////////////////////////

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
func (h *configResourceHandler) Setup(tx storage.Tx, isAdmin bool) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, isAdmin, h.r, noScope, h.input)
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
	if err := common.GetRequest(h.input, h.r); err != nil {
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
	common.SendResponse(h.item, h.w)
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
func (h *configResourceHandler) CheckIntegrity() (proto.Message, int, error) {
	return h.s.configCheckIntegrity(h.cfg, h.input.Modification, h.r)
}
func (h *configResourceHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return h.s.saveConfig(h.cfg, desc, typeName, h.r, h.id, h.item, h.save, h.input.Modification, h.tx)
}

//////////////////////////////////////////////////////////////////

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
func (h *configViewHandler) Setup(tx storage.Tx, isAdmin bool) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, isAdmin, h.r, noScope, h.input)
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
	if err := common.GetRequest(h.input, h.r); err != nil {
		return err
	}
	if h.input.Item == nil {
		h.input.Item = &pb.View{}
	}
	h.input.Item = receiveView(h.input.Item)
	return nil
}
func (h *configViewHandler) Get(name string) error {
	common.SendResponse(h.item, h.w)
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
func (h *configViewHandler) CheckIntegrity() (proto.Message, int, error) {
	return h.s.configCheckIntegrity(h.cfg, h.input.Modification, h.r)
}
func (h *configViewHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return h.s.saveConfig(h.cfg, desc, typeName, h.r, h.id, h.item, h.save, h.input.Modification, h.tx)
}

//////////////////////////////////////////////////////////////////

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
func (h *configIssuerHandler) Setup(tx storage.Tx, isAdmin bool) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, isAdmin, h.r, noScope, h.input)
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
	if err := common.GetRequest(h.input, h.r); err != nil {
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
	common.SendResponse(h.item, h.w)
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
func (h *configIssuerHandler) CheckIntegrity() (proto.Message, int, error) {
	return h.s.configCheckIntegrity(h.cfg, h.input.Modification, h.r)
}
func (h *configIssuerHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return h.s.saveConfig(h.cfg, desc, typeName, h.r, h.id, h.item, h.save, h.input.Modification, h.tx)
}

//////////////////////////////////////////////////////////////////

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
func (h *configSourceHandler) Setup(tx storage.Tx, isAdmin bool) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, isAdmin, h.r, noScope, h.input)
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
	if err := common.GetRequest(h.input, h.r); err != nil {
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
	common.SendResponse(h.item, h.w)
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
func (h *configSourceHandler) CheckIntegrity() (proto.Message, int, error) {
	return h.s.configCheckIntegrity(h.cfg, h.input.Modification, h.r)
}
func (h *configSourceHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return h.s.saveConfig(h.cfg, desc, typeName, h.r, h.id, h.item, h.save, h.input.Modification, h.tx)
}

//////////////////////////////////////////////////////////////////

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
func (h *configPolicyHandler) Setup(tx storage.Tx, isAdmin bool) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, isAdmin, h.r, noScope, h.input)
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
	if err := common.GetRequest(h.input, h.r); err != nil {
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
	common.SendResponse(h.item, h.w)
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
	h.item.Allow = h.input.Item.Allow
	h.item.Disallow = h.input.Item.Disallow
	h.item.Ui = h.input.Item.Ui
	h.save = h.item
	return nil
}
func (h *configPolicyHandler) Remove(name string) error {
	delete(h.cfg.Policies, name)
	h.save = &pb.Policy{}
	return nil
}
func (h *configPolicyHandler) CheckIntegrity() (proto.Message, int, error) {
	return h.s.configCheckIntegrity(h.cfg, h.input.Modification, h.r)
}
func (h *configPolicyHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return h.s.saveConfig(h.cfg, desc, typeName, h.r, h.id, h.item, h.save, h.input.Modification, h.tx)
}

//////////////////////////////////////////////////////////////////

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
func (h *configClaimDefinitionHandler) Setup(tx storage.Tx, isAdmin bool) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, isAdmin, h.r, noScope, h.input)
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
	if err := common.GetRequest(h.input, h.r); err != nil {
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
	common.SendResponse(h.item, h.w)
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
func (h *configClaimDefinitionHandler) CheckIntegrity() (proto.Message, int, error) {
	return h.s.configCheckIntegrity(h.cfg, h.input.Modification, h.r)
}
func (h *configClaimDefinitionHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return h.s.saveConfig(h.cfg, desc, typeName, h.r, h.id, h.item, h.save, h.input.Modification, h.tx)
}

//////////////////////////////////////////////////////////////////

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
func (h *configServiceTemplateHandler) Setup(tx storage.Tx, isAdmin bool) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, isAdmin, h.r, noScope, h.input)
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
	if err := common.GetRequest(h.input, h.r); err != nil {
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
	common.SendResponse(h.item, h.w)
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
func (h *configServiceTemplateHandler) CheckIntegrity() (proto.Message, int, error) {
	return h.s.configCheckIntegrity(h.cfg, h.input.Modification, h.r)
}
func (h *configServiceTemplateHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return h.s.saveConfig(h.cfg, desc, typeName, h.r, h.id, h.item, h.save, h.input.Modification, h.tx)
}

//////////////////////////////////////////////////////////////////

type configPersonaHandler struct {
	s     *Service
	w     http.ResponseWriter
	r     *http.Request
	input *pb.ConfigTestPersonaRequest
	item  *pb.TestPersona
	save  *pb.TestPersona
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
func (h *configPersonaHandler) Setup(tx storage.Tx, isAdmin bool) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, isAdmin, h.r, noScope, h.input)
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
	if err := common.GetRequest(h.input, h.r); err != nil {
		return err
	}
	if h.input.Item == nil {
		h.input.Item = &pb.TestPersona{}
	}
	if h.input.Item.IdToken == nil {
		h.input.Item.IdToken = &pb.TestPersona_TestIdentityToken{}
	}
	if h.input.Item.IdToken.StandardClaims == nil {
		h.input.Item.IdToken.StandardClaims = make(map[string]string)
	}
	if h.input.Item.Resources == nil {
		h.input.Item.Resources = make(map[string]*pb.AccessList)
	}
	if h.input.Item.Ui == nil {
		h.input.Item.Ui = make(map[string]string)
	}
	return nil
}
func (h *configPersonaHandler) Get(name string) error {
	common.SendResponse(h.item, h.w)
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
	h.item.IdToken = h.input.Item.IdToken
	h.item.Resources = h.input.Item.Resources
	h.item.Ui = h.input.Item.Ui
	h.save = h.item
	return nil
}
func (h *configPersonaHandler) Remove(name string) error {
	delete(h.cfg.TestPersonas, name)
	h.save = &pb.TestPersona{}
	return nil
}
func (h *configPersonaHandler) CheckIntegrity() (proto.Message, int, error) {
	return h.s.configCheckIntegrity(h.cfg, h.input.Modification, h.r)
}
func (h *configPersonaHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return h.s.saveConfig(h.cfg, desc, typeName, h.r, h.id, h.item, h.save, h.input.Modification, h.tx)
}

//////////////////////////////////////////////////////////////////

type configClientHandler struct {
	s     *Service
	w     http.ResponseWriter
	r     *http.Request
	input *pb.ConfigClientRequest
	item  *pb.Client
	save  *pb.Client
	cfg   *pb.DamConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func NewConfigClientHandler(s *Service, w http.ResponseWriter, r *http.Request) *configClientHandler {
	return &configClientHandler{
		s:     s,
		w:     w,
		r:     r,
		input: &pb.ConfigClientRequest{},
	}
}
func (h *configClientHandler) Setup(tx storage.Tx, isAdmin bool) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, isAdmin, h.r, noScope, h.input)
	h.cfg = cfg
	h.id = id
	h.tx = tx
	return status, err
}
func (h *configClientHandler) LookupItem(name string, vars map[string]string) bool {
	item, ok := h.cfg.Clients[name]
	if !ok {
		return false
	}
	h.item = item
	return true
}
func (h *configClientHandler) NormalizeInput(name string, vars map[string]string) error {
	if err := common.GetRequest(h.input, h.r); err != nil {
		return err
	}
	if h.input.Item == nil {
		h.input.Item = &pb.Client{}
	}
	// TODO: add some checks for client ID being allocated and/or matching the config.
	//if len(h.input.Item.ClientId) > 0 {
	//	return fmt.Errorf("client IDs are assigned and should not be provided by the API caller")
	//}
	if h.input.Item.Ui == nil {
		h.input.Item.Ui = make(map[string]string)
	}
	return nil
}
func (h *configClientHandler) Get(name string) error {
	common.SendResponse(h.item, h.w)
	return nil
}
func (h *configClientHandler) Post(name string) error {
	h.input.Item.ClientId = common.GenerateGUID()
	h.cfg.Clients[name] = h.input.Item
	h.save = h.input.Item
	return nil
}
func (h *configClientHandler) Put(name string) error {
	h.input.Item.ClientId = h.item.ClientId
	h.cfg.Clients[name] = h.input.Item
	h.save = h.input.Item
	return nil
}
func (h *configClientHandler) Patch(name string) error {
	h.input.Item.ClientId = h.item.ClientId
	proto.Merge(h.item, h.input.Item)
	h.item.Ui = h.input.Item.Ui
	h.save = h.item
	return nil
}
func (h *configClientHandler) Remove(name string) error {
	delete(h.cfg.Clients, name)
	h.save = &pb.Client{}
	return nil
}
func (h *configClientHandler) CheckIntegrity() (proto.Message, int, error) {
	return h.s.configCheckIntegrity(h.cfg, h.input.Modification, h.r)
}
func (h *configClientHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return h.s.saveConfig(h.cfg, desc, typeName, h.r, h.id, h.item, h.save, h.input.Modification, h.tx)
}

/////////////////////////////////////////////////////////
