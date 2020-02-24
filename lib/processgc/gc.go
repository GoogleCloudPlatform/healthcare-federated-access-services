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

// Package processgc provices an Account Manager Garbage Collection.
package processgc

import (
	"context"
	"strings"
	"time"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds" /* copybara-comment: clouds */
	processlib "github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/process" /* copybara-comment: process */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/timeutil" /* copybara-comment: timeutil */

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/process/v1" /* copybara-comment: go_proto */
)

const (
	keyScheduleFrequency    = time.Hour
	maxKeyScheduleFrequency = 12 * time.Hour
)

// KeyGC is a service account key garbage collector background process.
type KeyGC struct {
	name    string
	am      clouds.AccountManager
	process *processlib.Process
	wait    func(ctx context.Context, duration time.Duration) bool
}

// NewKeyGC creates a new key garbage collector.
func NewKeyGC(name string, warehouse clouds.AccountManager, store storage.Store, maxRequestedTTL time.Duration, keysPerAccount int) *KeyGC {
	k := &KeyGC{
		name: name,
		am:   warehouse,
	}
	defaultParams := &pb.Process_Params{
		IntParams: map[string]int64{
			"maxRequestedTtl": int64(maxRequestedTTL.Seconds()),
			"keysPerAccount":  int64(keysPerAccount),
			"keyTtl":          int64(timeutil.KeyTTL(maxRequestedTTL, keysPerAccount).Seconds()),
		},
	}
	// TODO: reverse the dependency, this package doesn't need to know about process.
	k.process = processlib.NewProcess(name, k, store, keyScheduleFrequency, defaultParams)
	return k
}

// RegisterWork adds a work item to the state for workers to process.
func (k *KeyGC) RegisterWork(workName string, params *pb.Process_Params, tx storage.Tx) (*pb.Process_Work, error) {
	return k.process.RegisterWork(workName, params, tx)
}

// UnregisterWork (eventually) removes a work item from the active state, and allows cleanup work to be performed.
func (k *KeyGC) UnregisterWork(workName string, tx storage.Tx) error {
	return k.process.UnregisterWork(workName, tx)
}

// UpdateSettings alters resource management settings.
func (k *KeyGC) UpdateSettings(maxRequestedTTL time.Duration, keysPerAccount int, tx storage.Tx) error {
	keyTTL := timeutil.KeyTTL(maxRequestedTTL, keysPerAccount)
	settings := &pb.Process_Params{
		IntParams: map[string]int64{
			"maxRequestedTtl": int64(maxRequestedTTL.Seconds()),
			"keysPerAccount":  int64(keysPerAccount),
			"keyTtl":          int64(keyTTL.Seconds()),
		},
	}
	scheduleFrequency := keyTTL / 10
	if scheduleFrequency > maxKeyScheduleFrequency {
		scheduleFrequency = maxKeyScheduleFrequency
	}
	return k.process.UpdateSettings(scheduleFrequency, settings, tx)
}

// WaitCondition registers a callback that is called and checks conditions before every wait cycle.
func (k *KeyGC) WaitCondition(fn func(ctx context.Context, duration time.Duration) bool) {
	k.wait = fn
}

// Run schedules a background process. Typically this will be on its own go routine.
func (k *KeyGC) Run(ctx context.Context) {
	k.process.Run(ctx)
}

// ProcessActiveWork has a worker perform the work needed to process an active work item.
func (k *KeyGC) ProcessActiveWork(ctx context.Context, state *pb.Process, workName string, work *pb.Process_Work, process *processlib.Process) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	accounts, err := k.am.GetServiceAccounts(ctx, workName)
	if err != nil {
		return err
	}

	for a := range accounts {
		if !isGarbageCollectAccount(a) {
			continue
		}

		process.AddWorkStats(1, "accounts", workName, state)
		keyTTL := work.Params.IntParams["keyTtl"]
		keysPerAccount := work.Params.IntParams["keysPerAccount"]
		got, rm, err := k.am.ManageAccountKeys(ctx, workName, a.ID, 0, time.Duration(keyTTL)*time.Second, time.Now(), keysPerAccount)
		if err != nil {
			run := process.AddWorkError(err, workName, state)
			if run != processlib.Continue {
				return nil
			}
			continue
		}
		process.AddWorkStats(float64(got), "keysKept", workName, state)
		process.AddWorkStats(float64(rm), "keysRemoved", workName, state)
	}
	return nil
}

// CleanupWork has a worker perform the work needed to clean up a work item that was active previously.
func (k *KeyGC) CleanupWork(ctx context.Context, state *pb.Process, workName string, process *processlib.Process) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	accounts, err := k.am.GetServiceAccounts(ctx, workName)
	if err != nil {
		return err
	}

	for a := range accounts {
		if !isGarbageCollectAccount(a) {
			continue
		}
		if err := k.am.RemoveServiceAccount(ctx, workName, a.ID); err != nil {
			process.AddWorkStats(1, "accountsDirty", workName, state)
			run := process.AddWorkError(err, workName, state)
			if run != processlib.Continue {
				return nil
			}
			continue
		}
		process.AddWorkStats(1, "accountsRemoved", workName, state)
	}
	return nil
}

// Wait indicates that the worker should wait for the next active cycle to begin.
func (k *KeyGC) Wait(ctx context.Context, duration time.Duration) bool {
	if k.wait != nil && !k.wait(ctx, duration) {
		return false
	}
	time.Sleep(duration)
	return true
}

func isGarbageCollectAccount(sa *clouds.Account) bool {
	return strings.Contains(sa.DisplayName, "@") || strings.Contains(sa.DisplayName, "|")
}
