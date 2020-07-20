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

package dam

import (
	"fmt"
	"net/http"
	"regexp"

	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/handlerfactory" /* copybara-comment: handlerfactory */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/lro" /* copybara-comment: lro */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
	ppb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/process/v1" /* copybara-comment: go_proto */
)

const (
	lroName = "lro"
)

var (
	uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

func (s *Service) lroFactory() *handlerfactory.Options {
	return &handlerfactory.Options{
		TypeName:            "lro",
		PathPrefix:          lroPath,
		HasNamedIdentifiers: true,
		Service: func() handlerfactory.Service {
			return newLROHandler(s)
		},
		NameChecker: map[string]*regexp.Regexp{"name": uuidRE},
	}
}

type lroHandler struct {
	s     *Service
	item  *ppb.Process_Work
	state string
	cfg   *pb.DamConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

// newLROHandler handles one LRO request
func newLROHandler(s *Service) *lroHandler {
	return &lroHandler{
		s:    s,
		item: &ppb.Process_Work{},
	}
}

func (h *lroHandler) Setup(r *http.Request, tx storage.Tx) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, r, noScope, nil)
	h.tx = tx
	h.cfg = cfg
	h.id = id
	return status, err
}

func (h *lroHandler) LookupItem(r *http.Request, name string, vars map[string]string) bool {
	err := h.s.store.ReadTx(storage.LongRunningOperationDatatype, storage.DefaultRealm, lro.Active, name, storage.LatestRev, h.item, h.tx)
	if err != nil && storage.ErrNotFound(err) {
		// Not found on the active queue, so try again on the inactive list.
		err = h.s.store.ReadTx(storage.LongRunningOperationDatatype, storage.DefaultRealm, lro.Inactive, name, storage.LatestRev, h.item, h.tx)
	}
	if err != nil {
		if storage.ErrNotFound(err) {
			h.state = "purged"
			return true
		}
		h.state = "unavailable"
		return true
	}
	h.state = lro.StateToString(h.item.GetStatus().GetState())
	return true
}

func (h *lroHandler) NormalizeInput(r *http.Request, name string, vars map[string]string) error {
	return nil
}

func (h *lroHandler) Get(r *http.Request, name string) (proto.Message, error) {
	return &ppb.WorkResponse{
		Id:      name,
		State:   h.state,
		Details: h.item,
	}, nil
}

func (h *lroHandler) Post(r *http.Request, name string) (proto.Message, error) {
	return nil, fmt.Errorf("POST not allowed")
}

func (h *lroHandler) Put(r *http.Request, name string) (proto.Message, error) {
	return nil, fmt.Errorf("PUT not allowed")
}

func (h *lroHandler) Patch(r *http.Request, name string) (proto.Message, error) {
	return nil, fmt.Errorf("PATCH not allowed")
}

func (h *lroHandler) Remove(r *http.Request, name string) (proto.Message, error) {
	return nil, fmt.Errorf("DELETE not allowed")
}

func (h *lroHandler) CheckIntegrity(*http.Request) *status.Status {
	return nil
}

func (h *lroHandler) Save(r *http.Request, tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return fmt.Errorf("save not allowed")
}
