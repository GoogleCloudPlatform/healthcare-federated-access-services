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

// Package process is for background processes and listed at the ../processes endpoint.
package process

import (
	"context"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"time"

	glog "github.com/golang/glog" /* copybara-comment */
	tspb "github.com/golang/protobuf/ptypes/timestamp" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
	"github.com/golang/protobuf/ptypes" /* copybara-comment */
	"github.com/pborman/uuid" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/process/v1" /* copybara-comment: go_proto */
)

var (
	instanceID = uuid.New()
)

// ErrorAction indicates how an AddError or AddWorkError should be handled.
type ErrorAction string

// Progress indicates how an update was handled.
type Progress string

const (
	maxWorkErrors  = 10
	maxTotalErrors = 25
	minJitter      = 5
	maxJitter      = 30

	// Continue indicates the error was within max error tolerance.
	Continue ErrorAction = "Continue"
	// Abort indicates this error exceeds max error tolerance.
	Abort ErrorAction = "Abort"

	// Completed indicates that execution has terminated normally due to completion of work.
	Completed Progress = "Completed"
	// Updated indicates that the state was updated in storage.
	Updated Progress = "Updated"
	// Merged indicates that the state was merged, then updated in storage.
	Merged Progress = "Merged"
	// Aborted indicates that errors caused execution to prematurely stop (incomplete).
	Aborted Progress = "Aborted"
	// Conflict indicates that the state ownership was taken over by another instance.
	// Unlike Aborted, the Conflict level indicates that any further writes of state
	// to storage should not be attempted.
	Conflict Progress = "Conflict"
	// None indicates that there was no storage update at this time.
	None Progress = "None"
)

// Worker represents a process that perform work on the set of work items provided.
type Worker interface {
	// ProcessActiveWork has a worker perform the work needed to process an active work item.
	ProcessActiveWork(ctx context.Context, state *pb.Process, workName string, work *pb.Process_Work, process *Process) error
	// CleanupWork has a worker perform the work needed to clean up a work item that was active previously.
	CleanupWork(ctx context.Context, state *pb.Process, workName string, process *Process) error
	// Wait indicates that the worker should wait for the next active cycle to begin. Return false to exit worker.
	Wait(ctx context.Context, duration time.Duration) bool
}

// Process is a background process that performs work at a scheduled frequency.
type Process struct {
	name                 string
	worker               Worker
	store                storage.Store
	mutex                sync.Mutex
	initialWaitDuration  time.Duration
	minScheduleFrequency time.Duration
	scheduleFrequency    time.Duration
	progressFrequency    time.Duration
	defaultSettings      *pb.Process_Params
	running              bool
}

// NewProcess creates a new process to perform work of a given name. It will trigger every "scheduleFrequency"
// and workers will report back status updates to the storage layer every "progressFrequency".
//   - If the process is not found in the storage layer, it will initialize with "defaultSettings".
//   - scheduleFrequency may be adjusted to meet schedule frequency constraints.
func NewProcess(name string, worker Worker, store storage.Store, scheduleFrequency time.Duration, defaultSettings *pb.Process_Params) *Process {
	rand.Seed(time.Now().UTC().UnixNano())
	p := &Process{
		name:                 name,
		worker:               worker,
		store:                store,
		mutex:                sync.Mutex{},
		initialWaitDuration:  time.Minute,
		minScheduleFrequency: 15 * time.Minute,
		defaultSettings:      defaultSettings,
		running:              false,
	}
	sf, pf := p.frequency(scheduleFrequency)
	p.scheduleFrequency = sf
	p.progressFrequency = pf
	return p
}

// ScheduleFrequency returns schedule frequency.
func (p *Process) ScheduleFrequency() time.Duration {
	return p.scheduleFrequency
}

// DefaultSettings returns the default settings.
func (p *Process) DefaultSettings() *pb.Process_Params {
	return p.defaultSettings
}

// RegisterWork adds a work item to the state for workers to process.
func (p *Process) RegisterWork(workName string, workParams *pb.Process_Params, tx storage.Tx) (_ *pb.Process_Work, ferr error) {
	if len(workName) == 0 {
		return nil, fmt.Errorf("process work item registration: cannot register an empty work item")
	}
	tx = p.store.LockTx(p.name, 0, tx)
	if tx == nil {
		return nil, fmt.Errorf("lock process registration failed: lock unavailable")
	}
	defer func() {
		err := tx.Finish()
		if ferr == nil {
			ferr = err
		}
	}()

	state, err := p.readState(tx)
	if err != nil {
		return nil, err
	}

	now := ptypes.TimestampNow()
	if workParams == nil {
		workParams = &pb.Process_Params{}
	}
	work := &pb.Process_Work{
		Modified: now,
		Params:   workParams,
		Status:   newStatus(pb.Process_Status_NEW),
	}
	old, ok := state.ActiveWork[workName]
	if ok && proto.Equal(old.Params, work.Params) {
		glog.Infof("process %q instance %q verified work item %q was already registered with the same parameters", p.name, instanceID, workName)
		return work, nil
	}
	state.ActiveWork[workName] = work
	delete(state.CleanupWork, workName)
	delete(state.DroppedWork, workName)

	state.SettingsTime = ptypes.TimestampNow()
	if err := p.writeState(state, tx); err != nil {
		return nil, err
	}
	glog.Infof("process %q instance %q registered work item %q settings: %+v", p.name, instanceID, workName, work.Params)
	return work, nil
}

// UnregisterWork (eventually) removes a work item from the active state, and allows cleanup work to be performed.
func (p *Process) UnregisterWork(workName string, tx storage.Tx) (ferr error) {
	tx = p.store.LockTx(p.name, 0, tx)
	if tx == nil {
		return fmt.Errorf("lock process registration failed: lock unavailable")
	}
	defer func() {
		err := tx.Finish()
		if ferr == nil {
			ferr = err
		}
	}()

	state, err := p.readState(tx)
	if err != nil {
		return err
	}

	_, dropped := state.DroppedWork[workName]
	_, cleanup := state.CleanupWork[workName]
	if dropped || cleanup {
		return nil
	}
	// Schedule for cleanup.
	delete(state.ActiveWork, workName)
	state.CleanupWork[workName] = ptypes.TimestampNow()
	state.SettingsTime = ptypes.TimestampNow()
	if err := p.writeState(state, tx); err != nil {
		return err
	}
	glog.Infof("process %s instance %q scheduling: work item %q scheduled for clean up", p.name, instanceID, workName)
	return nil
}

// UpdateSettings alters resource management settings.
func (p *Process) UpdateSettings(scheduleFrequency time.Duration, settings *pb.Process_Params, tx storage.Tx) (ferr error) {
	p.defaultSettings = settings

	tx = p.store.LockTx(p.name, 0, tx)
	if tx == nil {
		return fmt.Errorf("lock process to update settings failed: lock unavailable")
	}
	defer func() {
		err := tx.Finish()
		if ferr == nil {
			ferr = err
		}
	}()

	state, err := p.readState(tx)
	if err != nil {
		return err
	}

	state.Settings = settings
	state.SettingsTime = ptypes.TimestampNow()
	if scheduleFrequency > 0 {
		scheduleFrequency, progressFrequency := p.frequency(scheduleFrequency)
		state.ScheduleFrequency = ptypes.DurationProto(scheduleFrequency)

		p.mutex.Lock()
		p.scheduleFrequency = scheduleFrequency
		p.progressFrequency = progressFrequency
		p.mutex.Unlock()
	}

	if err := p.writeState(state, tx); err != nil {
		return err
	}
	return nil
}

// UpdateFlowControl alters settings for how flow of processing is managed. These are
// advanced settings and should be carefully managed when used outside of tests. These
// should be based on the size of the processing work between updates and the expected
// total time for each run with sufficient tolerance for errors and retries to minimize
// collisions with 2+ workers grabbing control of the state.
func (p *Process) UpdateFlowControl(initialWaitDuration, minScheduleFrequency, progressFrequency time.Duration) error {
	if p.running {
		return fmt.Errorf("UpdateFlowControl failed: background process is already running")
	}
	p.initialWaitDuration = initialWaitDuration
	p.minScheduleFrequency = minScheduleFrequency
	p.scheduleFrequency = minScheduleFrequency
	p.progressFrequency = progressFrequency
	return nil
}

// Run schedules a background process. Typically this will be on its own go routine.
func (p *Process) Run(ctx context.Context) {
	p.running = true
	freq := p.initialWaitDuration
	for {
		if !p.worker.Wait(ctx, p.sleepTime(freq)) {
			break
		}
		state, newfreq, err := p.start()
		if newfreq > 0 && freq != newfreq {
			freq = newfreq
			glog.Infof("process %q instance %q schedule frequency set to %q", p.name, instanceID, freq)
		}
		if state == nil || err != nil {
			continue
		}
		completion := pb.Process_Status_COMPLETED
		result, err := p.work(ctx, state)
		if err != nil && len(state.ProcessStatus.Errors) > 0 {
			glog.Infof("process %q instance %q errors during execution: %d total errors, exit error: %v, first processing error: %v", p.name, instanceID, state.ProcessStatus.TotalErrors, err, state.ProcessStatus.Errors[0])
			completion = pb.Process_Status_INCOMPLETE
		}
		// finish() will do final state bookkeeping before writing it to storage.
		// If we are in the Conflict state, we should not attempt to write at all.
		if result != Conflict {
			p.finish(state, completion)
		}
		glog.Infof("process %q instance %q completion: status=%q, %v", p.name, instanceID, result, statsToString(state.ProcessStatus.Stats))
	}
	glog.Infof("process %q instance %q instructed to exit", p.name, instanceID)
}

// Progress is called by workers every 1 or more units of work and may update the underlying state.
// Returns true if an update occured.
// Important note: take caution as maps may have been merged with data from storage layer. If so, Merged progress will be returned.
func (p *Process) Progress(state *pb.Process) (Progress, error) {
	now := time.Now()
	progressTime, err := ptypes.Timestamp(state.ProcessStatus.ProgressTime)
	if err != nil {
		state.ProcessStatus.ProgressTime = state.ProcessStatus.StartTime
		progressTime = time.Unix(0, 0)
	}
	p.mutex.Lock()
	cutoff := progressTime.Add(p.progressFrequency)
	p.mutex.Unlock()
	if now.Sub(cutoff) > 0 {
		return p.update(state)
	}
	return None, nil
}

// AddError will add error state to a given status block. Set "workStatus" to nil if
// it is not specific.
func (p *Process) AddError(err error, workStatus *pb.Process_Status, state *pb.Process) ErrorAction {
	now := ptypes.TimestampNow()
	action := Continue
	if workStatus != nil {
		workStatus.TotalErrors++
		workStatus.LastErrorTime = now
		if len(workStatus.Errors) < maxWorkErrors {
			workStatus.Errors = append(workStatus.Errors, &pb.Process_Error{Time: now, Text: err.Error()})
		} else {
			action = Abort
		}
	}
	state.ProcessStatus.TotalErrors++
	state.ProcessStatus.LastErrorTime = now
	if len(state.ProcessStatus.Errors) < maxTotalErrors {
		state.ProcessStatus.Errors = append(state.ProcessStatus.Errors, &pb.Process_Error{Time: now, Text: err.Error()})
	} else {
		action = Abort
	}
	return action
}

// AddWorkError will add error state to a given work item status block as well as the process status block.
func (p *Process) AddWorkError(err error, workName string, state *pb.Process) ErrorAction {
	work, ok := state.ActiveWork[workName]
	if ok {
		return p.AddError(err, work.Status, state)
	}
	return p.AddError(err, nil, state)
}

// AddStats will increment metrics of a given name within the process status.
func (p *Process) AddStats(count float64, name string, state *pb.Process) {
	val, ok := state.ProcessStatus.Stats[name]
	if !ok {
		val = 0
	}
	state.ProcessStatus.Stats[name] = val + count
}

// AddWorkStats will increment metrics of a given name within the work item and process status.
func (p *Process) AddWorkStats(count float64, stat, workName string, state *pb.Process) {
	work, ok := state.ActiveWork[workName]
	if ok {
		work.Status.Stats[stat] = work.Status.Stats[stat] + count
	}
	p.AddStats(count, "work."+stat, state)
}

func (p *Process) work(ctx context.Context, state *pb.Process) (Progress, error) {
	// Create stable lists that will be followed even if a merge occurs during
	// any Progress() updates.
	var active []string
	var cleanup []string
	var drop []string
	for work := range state.ActiveWork {
		active = append(active, work)
	}
	for work := range state.CleanupWork {
		cleanup = append(cleanup, work)
	}
	// Process in a consistent order makes progress reports easier to compare.
	sort.Strings(active)
	sort.Strings(cleanup)
	sort.Strings(drop)

	// Process active work.
	for _, workName := range active {
		work, ok := state.ActiveWork[workName]
		if !ok {
			// Was removed on merge.
			continue
		}
		p.AddStats(1, "workItems", state)
		work.Status = newStatus(pb.Process_Status_ACTIVE)
		err := p.worker.ProcessActiveWork(ctx, state, workName, work, p)
		if err == nil {
			p.setWorkState(pb.Process_Status_COMPLETED, workName, state)
		} else if p.AddWorkError(err, workName, state) == Abort {
			p.setWorkState(pb.Process_Status_ABORTED, workName, state)
			return Aborted, err
		} else {
			p.setWorkState(pb.Process_Status_INCOMPLETE, workName, state)
		}
		progress, err := p.Progress(state)
		if progress == Conflict || progress == Aborted {
			return progress, err
		}
	}

	// Process cleanup work.
	for _, workName := range cleanup {
		if _, ok := state.CleanupWork[workName]; !ok {
			// Was removed on merge.
			continue
		}
		errors := 0
		run := Continue
		err := p.worker.CleanupWork(ctx, state, workName, p)
		if err != nil && !ignoreCleanupError(err) {
			errors++
			err = fmt.Errorf("clean up work on item %q: %v", workName, err)
			run = p.AddError(err, nil, state)
		}
		if run == Abort {
			p.AddStats(1, "workItemsDirty", state)
			p.AddStats(1, "workItemsAborted", state)
			return Aborted, err
		}
		if errors == 0 {
			p.AddStats(1, "workItemsCleaned", state)
			if _, ok := state.ActiveWork[workName]; !ok {
				// Only add to the drop list because there were no errors to retry later and merge has not returned the work item to the active list.
				drop = append(drop, workName)
			}
		} else {
			p.AddStats(1, "workItemsDirty", state)
		}
		progress, err := p.Progress(state)
		if progress == Conflict || progress == Aborted {
			return progress, err
		}
	}

	// Move cleanup work to dropped work if no errors encountered during cleaning (i.e. it is on the drop list).
	now := ptypes.TimestampNow()
	for _, workName := range drop {
		delete(state.CleanupWork, workName)
		if _, ok := state.ActiveWork[workName]; ok {
			// Was added on merge, do not drop.
			continue
		}
		state.DroppedWork[workName] = now
	}
	return Completed, nil
}

func (p *Process) setWorkState(statusState pb.Process_Status_State, workName string, state *pb.Process) {
	work, ok := state.ActiveWork[workName]
	if !ok {
		return
	}
	work.Status.State = statusState
	if statusState == pb.Process_Status_COMPLETED {
		work.Status.FinishTime = ptypes.TimestampNow()
	}
}

func (p *Process) readState(tx storage.Tx) (*pb.Process, error) {
	state := &pb.Process{}
	err := p.store.ReadTx(storage.ProcessDataType, storage.DefaultRealm, storage.DefaultUser, p.name, storage.LatestRev, state, tx)
	p.setup(state)
	if err == nil || !storage.ErrNotFound(err) {
		return state, err
	}
	return state, nil
}

func (p *Process) writeState(state *pb.Process, tx storage.Tx) error {
	if err := p.store.WriteTx(storage.ProcessDataType, storage.DefaultRealm, storage.DefaultUser, p.name, storage.LatestRev, state, nil, tx); err != nil {
		err = fmt.Errorf("process %q instance %q write state failed: %v", p.name, instanceID, err)
		glog.Errorf(err.Error())
		return err
	}
	return nil
}

func (p *Process) start() (_ *pb.Process, _ time.Duration, ferr error) {
	tx := p.store.LockTx(p.name, 0, nil)
	if tx == nil {
		return nil, 0, nil
	}
	defer func() {
		err := tx.Finish()
		if ferr == nil {
			ferr = err
		}
	}()

	state, err := p.readState(tx)
	if err != nil {
		return nil, 0, err
	}

	// Always call setup() to add any structures that may not already be defined within the object.
	p.setup(state)
	freq, err := ptypes.Duration(state.ScheduleFrequency)
	if err != nil {
		freq = 0
	}

	// Determine if a run is needed given the cutoff time (i.e. time of next scheduled run)
	// and other timestamps that determine the current run state.
	cutoff := p.cutoff(state)
	if timeCompare(state.ProcessStatus.ProgressTime, cutoff) >= 0 {
		if state.ProcessStatus.FinishTime == nil || timeCompare(state.ProcessStatus.StartTime, state.SettingsTime) > 0 {
			// Do not process for one of the following reasons:
			// 1. Another working already has been active recently and is likely still active.
			// 2. The previous worker had started more recently than when the settings has changed.
			return nil, freq, nil
		}
	}

	// This worker will process this scheduled slot. Prepare to run.
	state.ProcessName = p.name
	state.Instance = instanceID
	// Set up a new process status object to track this worker run.
	state.ProcessStatus = newStatus(pb.Process_Status_ACTIVE)
	// Save the current state to inform other workers that this worker owns processing for this scheduled run.
	if err := p.writeState(state, tx); err != nil {
		return nil, freq, err
	}
	glog.Infof("background process %q instance %q active...", p.name, instanceID)
	// Returning will release the lock, and allow other workers to check the current state.
	return state, freq, nil
}

func (p *Process) update(state *pb.Process) (_ Progress, ferr error) {
	state.ProcessStatus.ProgressTime = state.ProcessStatus.FinishTime
	if state.ProcessStatus.ProgressTime == nil {
		state.ProcessStatus.ProgressTime = ptypes.TimestampNow()
	}

	tx := p.store.LockTx(p.name, 0, nil)
	if tx == nil {
		err := fmt.Errorf("process %q instance %q lock unavailable", p.name, instanceID)
		glog.Infof(err.Error())
		p.AddError(err, nil, state)
		return None, err
	}
	defer func() {
		err := tx.Finish()
		if ferr == nil {
			ferr = err
		}
	}()

	storeState := &pb.Process{}
	if err := p.store.ReadTx(storage.ProcessDataType, storage.DefaultRealm, storage.DefaultUser, p.name, storage.LatestRev, storeState, tx); err != nil {
		err = fmt.Errorf("reading process state %q: %v", p.name, err)
		glog.Infof(err.Error())
		p.AddError(err, nil, state)
		return None, err
	}

	// Check to see if this process instance still owns the state.
	if storeState.Instance != instanceID {
		// Another process has taken over. Abandon this run.
		err := fmt.Errorf("process %q instance %q lost state ownership: state now owned by instance %q", p.name, instanceID, storeState.Instance)
		p.AddError(err, nil, state)
		return Conflict, err
	}

	progress := Updated
	if timeCompare(storeState.SettingsTime, state.ProcessStatus.StartTime) > 0 {
		progress = p.mergeProcessState(state, storeState)
	}

	if err := p.writeState(state, tx); err != nil {
		p.AddError(err, nil, state)
		return progress, err
	}

	return progress, nil
}

func (p *Process) finish(state *pb.Process, completion pb.Process_Status_State) {
	state.ProcessStatus.FinishTime = ptypes.TimestampNow()
	state.ProcessStatus.State = completion
	if _, ok := state.ProcessStatus.Stats["workItems"]; !ok {
		p.AddStats(0, "workItems", state)
	}
	aggregateStats(state)
	p.update(state)
}

func (p *Process) mergeProcessState(state, src *pb.Process) Progress {
	var rm []string
	now := ptypes.TimestampNow()

	// ActiveWork: take params etc from src, but retain some processing state.
	// Remove from ActiveWork if work item is not in src.
	for k, destv := range state.ActiveWork {
		if srcp, ok := src.ActiveWork[k]; ok {
			srcp.Status = destv.Status
			state.ActiveWork[k] = srcp
		} else {
			rm = append(rm, k)
		}
	}
	for _, k := range rm {
		delete(state.ActiveWork, k)
		if _, ok := state.CleanupWork[k]; !ok {
			state.CleanupWork[k] = now
		}
	}
	// Copy over active work items from src that are not currently in processing state.
	for k, srcv := range src.ActiveWork {
		if _, ok := state.ActiveWork[k]; !ok {
			state.ActiveWork[k] = srcv
		}
	}

	// CleanupWork: add all from src.
	for k, v := range src.CleanupWork {
		state.CleanupWork[k] = v
		if _, ok := state.DroppedWork[k]; ok {
			delete(state.DroppedWork, k)
		}
		if _, ok := state.ActiveWork[k]; ok {
			delete(state.CleanupWork, k)
		}
	}

	// DroppedWork: will only have changed in some error states, add from src
	// if not on other lists. Timestamp of when dropped is not critical.
	for k, v := range src.DroppedWork {
		_, active := state.ActiveWork[k]
		_, clean := state.CleanupWork[k]
		_, drop := state.DroppedWork[k]
		if !active && !clean && !drop {
			state.CleanupWork[k] = v
		}
	}
	rm = []string{}
	for k := range state.DroppedWork {
		_, active := state.ActiveWork[k]
		_, clean := state.CleanupWork[k]
		if active || clean {
			rm = append(rm, k)
		}
	}
	for _, work := range rm {
		delete(state.DroppedWork, work)
	}

	// Keep ProcessName, Instance, ProcessStatus, and AggregateStats.
	// Take remaining items from src.
	state.ScheduleFrequency = src.ScheduleFrequency
	state.Settings = src.Settings
	state.SettingsTime = now // reflect this merge

	return Merged
}

func newStatus(statusState pb.Process_Status_State) *pb.Process_Status {
	now := ptypes.TimestampNow()
	return &pb.Process_Status{
		StartTime:    now,
		ProgressTime: now,
		Stats:        map[string]float64{},
		Errors:       []*pb.Process_Error{},
		State:        statusState,
	}
}

func timeCompare(a, b *tspb.Timestamp) float64 {
	at, err := ptypes.Timestamp(a)
	if err != nil {
		at = time.Unix(0, 0)
	}
	bt, err := ptypes.Timestamp(b)
	if err != nil {
		bt = time.Unix(0, 0)
	}
	return at.Sub(bt).Seconds()
}

func (p *Process) cutoff(state *pb.Process) *tspb.Timestamp {
	cutoff := int64(0)
	now := time.Now().Unix()

	d, err := ptypes.Duration(state.ScheduleFrequency)
	if err != nil {
		d = time.Hour
	}
	freq := int64(d.Seconds())
	if freq < 1 {
		freq = 1
	}
	c := int64(now/freq) * freq
	if cutoff == 0 || c < cutoff {
		cutoff = c
	}

	ts, err := ptypes.TimestampProto(time.Unix(cutoff, 0))
	if err != nil {
		return nil
	}
	return ts
}

func (p *Process) setup(state *pb.Process) {
	if state.ActiveWork == nil {
		state.ActiveWork = make(map[string]*pb.Process_Work)
	}
	if state.CleanupWork == nil {
		state.CleanupWork = make(map[string]*tspb.Timestamp)
	}
	if state.DroppedWork == nil {
		state.DroppedWork = make(map[string]*tspb.Timestamp)
	}
	if state.ProcessStatus == nil {
		state.ProcessStatus = &pb.Process_Status{
			Stats: make(map[string]float64),
		}
	}
	if state.AggregateStats == nil {
		state.AggregateStats = make(map[string]float64)
	}

	state.ProcessName = p.name
	freq, err := ptypes.Duration(state.ScheduleFrequency)
	if err != nil || freq == 0 {
		p.mutex.Lock()
		state.ScheduleFrequency = ptypes.DurationProto(p.scheduleFrequency)
		p.mutex.Unlock()
	}
	if state.Settings == nil {
		state.Settings = p.defaultSettings
		state.SettingsTime = ptypes.TimestampNow()
	}
}

func (p *Process) sleepTime(freq time.Duration) time.Duration {
	secs := freq.Seconds()
	if secs < 1 {
		return freq
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Calculate the duration until the next start cycle should begin, then add some jitter.
	now := time.Now().Unix()
	next := (int64(now/int64(secs)) + 1) * int64(secs)
	secs = float64(next - now)
	// Add a small amount of random jitter to avoid some lock contention.
	jitterSeconds := minJitter + rand.Float64()*(maxJitter-minJitter)
	ns := (secs + jitterSeconds) * 1e9
	return time.Duration(ns)
}

func aggregateStats(state *pb.Process) {
	src := state.ProcessStatus.Stats
	dest := state.AggregateStats

	src["errors"] = float64(state.ProcessStatus.TotalErrors)
	src["duration"] = timeCompare(state.ProcessStatus.FinishTime, state.ProcessStatus.StartTime)
	src["runs"] = 1
	src["state."+strings.ToLower(state.ProcessStatus.State.String())] = 1

	for k, v := range src {
		prev, ok := dest[k]
		if !ok {
			prev = 0
		}
		dest[k] = prev + v
	}
}

func (p *Process) frequency(scheduleFrequency time.Duration) (time.Duration, time.Duration) {
	// Adjust processFrequency and progressFrequency such that:
	// 1. Workers do not fire too often, causing timing errors.
	// 2. Progress occurs frequently enough that lock ownership remains in place with occasional update() errors.
	if scheduleFrequency < p.minScheduleFrequency {
		scheduleFrequency = p.minScheduleFrequency
	}
	maxProgressFrequency := p.minScheduleFrequency / 3
	progressFrequency := scheduleFrequency / 10
	if progressFrequency > maxProgressFrequency {
		progressFrequency = maxProgressFrequency
	}
	return scheduleFrequency, progressFrequency
}

func statsToString(stats map[string]float64) string {
	out := ""
	for k, v := range stats {
		if len(out) > 0 {
			out += ", "
		}
		out += fmt.Sprintf("%s=%g", k, v)
		if k == "duration" {
			out += "s" // tag the units as seconds
		}
	}
	return out
}

// TODO: use new status errors and detect this better
func ignoreCleanupError(err error) bool {
	text := err.Error()
	return strings.Contains(text, "Error 403") || strings.Contains(text, "Error 404")
}
