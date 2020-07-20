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

// Package fakelro provides a minimal fake LRO background process for
// testing purposes.
package fakelro

import (
	"context"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/lro" /* copybara-comment: lro */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/process/v1" /* copybara-comment: go_proto */
)

// Service is a fake long running operation service.
type Service struct {
}

// New creates a fake LRO processing routine that holds multiple LROs that share
// the same setup parameters.
func New() lro.LRO {
	return &Service{}
}

// AddRealmRemoval adds a LRO work item for the stated goal to the state for workers to process.
func (s *Service) AddRealmRemoval(id, realm string, identity *ga4gh.Identity, tx storage.Tx) (*pb.Process_Work, error) {
	return &pb.Process_Work{}, nil
}

// Remove (eventually) removes a LRO work item from the active state, and allows cleanup work to be performed.
func (s *Service) Remove(id string, tx storage.Tx) error {
	return nil
}

// Run schedules a background process. Typically this will be on its own go routine.
func (s *Service) Run(ctx context.Context) {
}
