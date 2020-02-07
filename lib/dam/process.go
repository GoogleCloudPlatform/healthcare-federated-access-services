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
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/gcp" /* copybara-comment: gcp */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
)

func (s *Service) processesFactory() *httputil.HandlerFactory {
	return &httputil.HandlerFactory{
		TypeName:            "processes",
		PathPrefix:          processesPath,
		HasNamedIdentifiers: false,
		NewHandler: func(w http.ResponseWriter, r *http.Request) httputil.HandlerInterface {
			return NewProcessesHandler(s, w, r)
		},
	}
}

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
func (h *processesHandler) Setup(tx storage.Tx) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, h.r, noScope, h.input)
	h.tx = tx
	h.cfg = cfg
	h.id = id
	return status, err
}
func (h *processesHandler) LookupItem(name string, vars map[string]string) bool {
	h.item = make(map[string]*pb.BackgroundProcess)
	m := make(map[string]map[string]proto.Message)
	_, err := h.s.store.MultiReadTx(gcp.BackgroundProcessDataType, storage.DefaultRealm, storage.DefaultUser, nil, 0, storage.MaxPageSize, m, &pb.BackgroundProcess{}, h.tx)
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
	if err := httputil.GetRequest(h.input, h.r); err != nil {
		return err
	}
	return nil
}
func (h *processesHandler) Get(name string) error {
	if h.item != nil {
		httputil.SendResponse(&pb.BackgroundProcessesResponse{
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
func (h *processesHandler) CheckIntegrity() *status.Status {
	return nil
}
func (h *processesHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return fmt.Errorf("save not allowed")
}

/////////////////////////////////////////////////////////

func (s *Service) processFactory() *httputil.HandlerFactory {
	return &httputil.HandlerFactory{
		TypeName:            "process",
		PathPrefix:          processPath,
		HasNamedIdentifiers: true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) httputil.HandlerInterface {
			return NewProcessHandler(s, w, r)
		},
	}
}

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
func (h *processHandler) Setup(tx storage.Tx) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, h.r, noScope, h.input)
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
	if err := httputil.GetRequest(h.input, h.r); err != nil {
		return err
	}
	return nil
}
func (h *processHandler) Get(name string) error {
	if h.item != nil {
		httputil.SendResponse(&pb.BackgroundProcessResponse{
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
func (h *processHandler) CheckIntegrity() *status.Status {
	return nil
}
func (h *processHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return fmt.Errorf("save not allowed")
}
