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

	"github.com/golang/protobuf/proto" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/handlerfactory" /* copybara-comment: handlerfactory */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
	ppb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/process/v1" /* copybara-comment: go_proto */
)

func (s *Service) processesFactory() *handlerfactory.HandlerFactory {
	return &handlerfactory.HandlerFactory{
		TypeName:            "processes",
		PathPrefix:          processesPath,
		HasNamedIdentifiers: false,
		NewHandler: func(r *http.Request) handlerfactory.HandlerInterface {
			return NewProcessesHandler(s, r)
		},
	}
}

type processesHandler struct {
	s     *Service
	r     *http.Request
	input *pb.BackgroundProcessesRequest
	item  map[string]*ppb.Process
	cfg   *pb.DamConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func NewProcessesHandler(s *Service, r *http.Request) *processesHandler {
	return &processesHandler{
		s:     s,
		r:     r,
		input: &pb.BackgroundProcessesRequest{},
	}
}
func (h *processesHandler) Setup(tx storage.Tx) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, h.r, noScope, h.input)
	h.tx = tx
	h.cfg = cfg
	h.id = id
	return status, err
}
func (h *processesHandler) LookupItem(name string, vars map[string]string) bool {
	h.item = make(map[string]*ppb.Process)
	m := make(map[string]map[string]proto.Message)
	_, err := h.s.store.MultiReadTx(storage.ProcessDataType, storage.DefaultRealm, storage.DefaultUser, nil, 0, storage.MaxPageSize, m, &ppb.Process{}, h.tx)
	if err != nil {
		return false
	}
	for _, userVal := range m {
		for k, v := range userVal {
			if process, ok := v.(*ppb.Process); ok {
				h.item[k] = process
			}
		}
	}
	return true
}
func (h *processesHandler) NormalizeInput(name string, vars map[string]string) error {
	if err := httputil.DecodeProtoReq(h.input, h.r); err != nil {
		return err
	}
	return nil
}
func (h *processesHandler) Get(name string) (proto.Message, error) {
	if h.item != nil {
		return &pb.BackgroundProcessesResponse{Processes: h.item}, nil
	}
	return nil, nil
}
func (h *processesHandler) Post(name string) (proto.Message, error) {
	return nil, fmt.Errorf("POST not allowed")
}
func (h *processesHandler) Put(name string) (proto.Message, error) {
	return nil, fmt.Errorf("PUT not allowed")
}
func (h *processesHandler) Patch(name string) (proto.Message, error) {
	return nil, fmt.Errorf("PATCH not allowed")
}
func (h *processesHandler) Remove(name string) (proto.Message, error) {
	return nil, fmt.Errorf("DELETE not allowed")
}
func (h *processesHandler) CheckIntegrity() *status.Status {
	return nil
}
func (h *processesHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return fmt.Errorf("save not allowed")
}

/////////////////////////////////////////////////////////

func (s *Service) processFactory() *handlerfactory.HandlerFactory {
	return &handlerfactory.HandlerFactory{
		TypeName:            "process",
		PathPrefix:          processPath,
		HasNamedIdentifiers: true,
		NewHandler: func(r *http.Request) handlerfactory.HandlerInterface {
			return NewProcessHandler(s, r)
		},
	}
}

type processHandler struct {
	s     *Service
	r     *http.Request
	input *pb.BackgroundProcessRequest
	item  *ppb.Process
	cfg   *pb.DamConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func NewProcessHandler(s *Service, r *http.Request) *processHandler {
	return &processHandler{
		s:     s,
		r:     r,
		input: &pb.BackgroundProcessRequest{},
	}
}
func (h *processHandler) Setup(tx storage.Tx) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, h.r, noScope, h.input)
	h.tx = tx
	h.cfg = cfg
	h.id = id
	return status, err
}
func (h *processHandler) LookupItem(name string, vars map[string]string) bool {
	h.item = &ppb.Process{}
	err := h.s.store.ReadTx(storage.ProcessDataType, storage.DefaultRealm, storage.DefaultUser, name, storage.LatestRev, h.item, h.tx)
	if err != nil {
		return false
	}
	return true
}
func (h *processHandler) NormalizeInput(name string, vars map[string]string) error {
	if err := httputil.DecodeProtoReq(h.input, h.r); err != nil {
		return err
	}
	return nil
}
func (h *processHandler) Get(name string) (proto.Message, error) {
	if h.item != nil {
		return &pb.BackgroundProcessResponse{Process: h.item}, nil
	}
	return nil, nil
}
func (h *processHandler) Post(name string) (proto.Message, error) {
	return nil, fmt.Errorf("POST not allowed")
}
func (h *processHandler) Put(name string) (proto.Message, error) {
	return nil, fmt.Errorf("PUT not allowed")
}
func (h *processHandler) Patch(name string) (proto.Message, error) {
	return nil, fmt.Errorf("PATCH not allowed")
}
func (h *processHandler) Remove(name string) (proto.Message, error) {
	return nil, fmt.Errorf("DELETE not allowed")
}
func (h *processHandler) CheckIntegrity() *status.Status {
	return nil
}
func (h *processHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return fmt.Errorf("save not allowed")
}
