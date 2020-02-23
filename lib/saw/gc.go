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

package saw

import (
	"context"
	"time"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
)

// TODO: remove once the dependency between KeyGC and SAW are reversed.

// Run starts background processes of AccountWarehouse.
func (wh *AccountWarehouse) Run(ctx context.Context) {
	// TODO: fix input parameters based on config file.
	wh.keyGC.Run(ctx)
}

// RegisterAccountProject adds a project to the state for workers to process.
func (wh *AccountWarehouse) RegisterAccountProject(project string, tx storage.Tx) error {
	_, err := wh.keyGC.RegisterWork(project, nil, tx)
	return err
}

// UnregisterAccountProject (eventually) removes a project from the active state, and allows cleanup work to be performed.
func (wh *AccountWarehouse) UnregisterAccountProject(project string, tx storage.Tx) error {
	return wh.keyGC.UnregisterWork(project, tx)
}

// UpdateSettings alters resource management settings.
func (wh *AccountWarehouse) UpdateSettings(maxRequestedTTL time.Duration, keysPerAccount int, tx storage.Tx) error {
	return wh.keyGC.UpdateSettings(maxRequestedTTL, keysPerAccount, tx)
}
