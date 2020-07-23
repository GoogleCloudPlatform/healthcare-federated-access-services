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

// Package lro provides Long Running Operation (LRO) background processing.
package lro

import (
	"context"
	"fmt"
	"time"

	"github.com/golang/protobuf/ptypes" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	processlib "github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/process" /* copybara-comment: process */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/process/v1" /* copybara-comment: go_proto */
)

const (
	// Active indicates the item is in the queue to be processed, or is being processed.
	Active = "active"
	// Inactive indicates the item has been ABORTED or COMPLETED
	Inactive = "inactive"

	keyRealm       = "realm"
	opRealmRemoval = "remove-realm"
	scheduleFactor = 5 // schedule election ~5x longer than max expected progress frequency to avoid race conditions
)

var (
	// If this worker performed work this recently, then it is considered a candidate to wake more quickly
	detectMasterDuration           = 10 * time.Second
	retainCompletionStatusDuration = 7 * 24 * time.Hour
)

// LRO is an interface for long running operations.
type LRO interface {
	AddRealmRemoval(id, realm string, identity *ga4gh.Identity, tx storage.Tx) (*pb.Process_Work, error)
	Remove(id string, tx storage.Tx) error
	Run(ctx context.Context)
}

// Service is a long running operation service.
type Service struct {
	name          string
	store         storage.Store
	last          time.Time
	wakeFrequency time.Duration
	process       *processlib.Process
	wait          func(ctx context.Context, duration time.Duration) bool
}

// New creates a new LRO processing routine that holds multiple LROs that share
// the same setup parameters.
func New(name string, wakeFrequency, maxProgress time.Duration, store storage.Store, tx storage.Tx) (*Service, error) {
	lro := &Service{
		name:          name,
		store:         store,
		wakeFrequency: wakeFrequency,
		last:          time.Now(), // this will wake on wakeFrequency to try to win the election
	}
	max := int64(maxProgress.Seconds())
	schedule := max * scheduleFactor
	defaultParams := &pb.Process_Params{
		IntParams: map[string]int64{
			"maxProgressDuration": max,
			"scheduleFrequency":   schedule,
			"wakeFrequency":       int64(wakeFrequency.Seconds()),
		},
	}
	scheduleDuration := time.Duration(schedule) * time.Second
	lro.process = processlib.NewProcess(name, lro, store, scheduleDuration, defaultParams)
	// Use advanced controls to check soon after startup and use a shorter scheduleDuration given frequent progress updates.
	lro.process.UpdateFlowControl(30*time.Second, scheduleDuration, maxProgress)
	if _, err := lro.process.RegisterWork("lro", &pb.Process_Params{IntParams: map[string]int64{}}, tx); err != nil {
		return nil, err
	}
	return lro, nil
}

// StateToString offers a human-readable label for a State enum.
func StateToString(state pb.Process_Status_State) string {
	switch state {
	case pb.Process_Status_NEW:
		return "queued"
	case pb.Process_Status_ACTIVE:
		return "active"
	case pb.Process_Status_ABORTED:
		return "aborted"
	case pb.Process_Status_INCOMPLETE:
		return "incomplete"
	case pb.Process_Status_COMPLETED:
		return "completed"
	}
	return "unspecified"
}

// AddRealmRemoval adds a LRO work item for the stated goal to the state for workers to process.
func (s *Service) AddRealmRemoval(id, realm string, identity *ga4gh.Identity, tx storage.Tx) (*pb.Process_Work, error) {
	work := createWork(opRealmRemoval, id, keyRealm, realm, fmt.Sprintf("remove realm %q", realm), identity)
	if err := s.store.WriteTx(storage.LongRunningOperationDatatype, storage.DefaultRealm, Active, id, storage.LatestRev, work, nil, tx); err != nil {
		return nil, err
	}
	return work, nil
}

// Remove deletes one LRO work item from the active queue or inactive list. It does not provide any cleanup if the
// state is partial. Depending on execution, this deletion could later be rewritten by an active processing agent,
// so deleting is a best effort.
func (s *Service) Remove(id string, tx storage.Tx) error {
	// Silent on Not Found errors.
	if err := s.store.DeleteTx(storage.LongRunningOperationDatatype, storage.DefaultRealm, Active, id, storage.LatestRev, tx); err != nil && !storage.ErrNotFound(err) {
		return err
	}
	if err := s.store.DeleteTx(storage.LongRunningOperationDatatype, storage.DefaultRealm, Inactive, id, storage.LatestRev, tx); err != nil && !storage.ErrNotFound(err) {
		return err
	}
	return nil
}

// WaitCondition registers a callback that is called and checks conditions before every wait cycle.
func (s *Service) WaitCondition(fn func(ctx context.Context, duration time.Duration) bool) {
	s.wait = fn
}

// Run schedules a background process. Typically this will be on its own go routine.
func (s *Service) Run(ctx context.Context) {
	s.process.Run(ctx)
}

// ProcessActiveWork has a worker perform the work needed to process an active work item.
func (s *Service) ProcessActiveWork(ctx context.Context, state *pb.Process, workName string, work *pb.Process_Work, process *processlib.Process) error {
	var tx storage.Tx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// For moving active work to the inactive pile.
	move := make(map[string]*pb.Process_Work)

	var abort error
	for abort == nil {
		results, err := s.store.MultiReadTx(storage.LongRunningOperationDatatype, storage.DefaultRealm, Active, storage.MatchAllIDs, nil, 0, 25, &pb.Process_Work{}, tx)
		if err != nil {
			process.AddWorkError(err, workName, state)
			return err
		}
		if len(results.Entries) == 0 {
			break
		}
		for _, entry := range results.Entries {
			item, ok := entry.Item.(*pb.Process_Work)
			if !ok {
				err := fmt.Errorf("cast to process work")
				if process.AddWorkError(err, workName, state) != processlib.Continue {
					abort = err
					break
				}
				continue
			}
			markStarted(item)
			strParams := item.GetParams().GetStringParams()
			op := strParams["operation"]
			// Do not return early from here so we keep moving last forward, even when errors occur.
			var err error
			action := processlib.Continue
			st := item.GetStatus()
			switch op {
			// Add all supported operations to this switch.
			case opRealmRemoval:
				action, err = s.removeRealm(ctx, entry.ItemID, item, state, process)
			case "":
				st.State = pb.Process_Status_ABORTED
				err = fmt.Errorf("missing operation")
			default:
				st.State = pb.Process_Status_ABORTED
				err = fmt.Errorf("unknown operation %q", op)
			}
			if st.State == pb.Process_Status_ABORTED {
				move[entry.ItemID] = item
			}
			if err != nil {
				if process.AddWorkError(err, workName, state) != processlib.Continue {
					markIncomplete(item)
					abort = err
					break
				}
			}
			if action != processlib.Continue {
				markIncomplete(item)
				st.State = pb.Process_Status_INCOMPLETE
				abort = err
				break
			}
			markCompleted(item)
			move[entry.ItemID] = item
			process.Progress(state)
		}
		for id, item := range move {
			if err := s.store.WriteTx(storage.LongRunningOperationDatatype, storage.DefaultRealm, Inactive, id, storage.LatestRev, item, nil, tx); err != nil {
				process.AddWorkError(err, workName, state)
				continue
			}
			if err := s.store.DeleteTx(storage.LongRunningOperationDatatype, storage.DefaultRealm, Active, id, storage.LatestRev, tx); err != nil {
				process.AddWorkError(err, workName, state)
			}
		}
		// Always update last to show we hold the master key and should be the one to wake up early.
		s.last = time.Now()
		if abort != nil {
			break
		}
	}

	return abort
}

func markStarted(item *pb.Process_Work) {
	now := ptypes.TimestampNow()
	st := item.GetStatus()
	st.StartTime = now
	st.ProgressTime = now
	st.State = pb.Process_Status_ACTIVE
	lroStats(float64(1), "runs", item)
}

func markIncomplete(item *pb.Process_Work) {
	st := item.GetStatus()
	if st.State != pb.Process_Status_ABORTED {
		st.State = pb.Process_Status_INCOMPLETE
	}
	lroStats(float64(1), "state."+StateToString(st.State), item)
	markEnded(item)
}

func markCompleted(item *pb.Process_Work) {
	st := item.GetStatus()
	st.State = pb.Process_Status_COMPLETED
	lroStats(float64(1), "state."+StateToString(st.State), item)
	markEnded(item)
}

func markEnded(item *pb.Process_Work) {
	now := ptypes.TimestampNow()
	st := item.GetStatus()
	st.FinishTime = now
	st.ProgressTime = now
	if st.StartTime != nil {
		duration := now.AsTime().Sub(st.StartTime.AsTime()).Seconds()
		lroStats(duration, "duration", item)
	}
}

func lroStats(count float64, name string, item *pb.Process_Work) {
	st := item.GetStatus()
	stat := st.GetStats()
	if stat == nil {
		st.Stats = make(map[string]float64)
		stat = st.Stats
	}
	val, ok := stat[name]
	if !ok {
		val = 0
	}
	stat[name] = val + count
}

func (s *Service) removeRealm(ctx context.Context, id string, item *pb.Process_Work, state *pb.Process, process *processlib.Process) (processlib.ErrorAction, error) {
	params := item.GetParams().GetStringParams()
	realm := params[keyRealm]
	if len(realm) == 0 {
		err := fmt.Errorf("empty realm name")
		process.AddError(err, item.GetStatus(), state)
		return processlib.Abort, err
	}
	maxEntries := 500
	for i := 0; true; i++ {
		count, err := s.store.Wipe(ctx, realm, i, maxEntries)
		if err != nil && process.AddError(err, item.GetStatus(), state) != processlib.Continue {
			return processlib.Abort, err
		}
		// Stats for the background process that manages all LRO work.
		process.AddStats(float64(count), "removeRealm.itemsRemoved", state)
		// Stats specifically for this this LRO work object that is stored in a separate LRO object.
		lroStats(float64(count), "removeRealm.itemsRemoved", item)
		if count < maxEntries {
			break
		}
		process.Progress(state)
	}
	return processlib.Continue, nil
}

// CleanupWork has a worker perform the work needed to clean up a work item that was active previously.
func (s *Service) CleanupWork(ctx context.Context, state *pb.Process, workName string, process *processlib.Process) error {
	return nil
}

// Wait indicates that the worker should wait for the next active cycle to begin.
func (s *Service) Wait(ctx context.Context, schedule time.Duration) bool {
	if time.Now().Sub(s.last) < detectMasterDuration {
		// We should wait only a short while
		schedule = s.wakeFrequency
	}
	if s.wait != nil {
		if !s.wait(ctx, schedule) {
			return false
		}
	} else {
		time.Sleep(schedule)
	}
	return true
}

func createWork(op, id, key, value, label string, identity *ga4gh.Identity) *pb.Process_Work {
	work := &pb.Process_Work{
		// Modified is for the settings change timestamp.
		Modified: ptypes.TimestampNow(),
		Params: &pb.Process_Params{
			StringParams: map[string]string{
				"id":        id,
				"operation": op,
				"label":     label,
				key:         value,
			},
		},
		Status: &pb.Process_Status{
			TotalErrors: 0,
			State:       pb.Process_Status_NEW,
		},
	}
	if identity != nil {
		work.Params.StringParams["subject"] = identity.Subject
		work.Params.StringParams["issuer"] = identity.Issuer
		work.Params.StringParams["email"] = identity.Email
	}
	return work
}
