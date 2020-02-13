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
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common" /* copybara-comment: common */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/process/v1" /* copybara-comment: go_proto */
)

var (
	instanceID = common.GenerateGUID()
)

// ErrorAction indicates how an AddError or AddProjectError should be handled.
type ErrorAction string

// Progress indicates how an update was handled.
type Progress string

const (
	maxProjectErrors = 10
	maxTotalErrors   = 25
	minJitter        = 5
	maxJitter        = 30

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

// Process is a background process that performs work at a scheduled frequency.
type Process struct {
	name              string
	worker            Worker
	store             storage.Store
	mutex             sync.Mutex
	scheduleFrequency time.Duration
	progressFrequency time.Duration
	defaultSettings   *pb.Process_Params
}

// Worker represents a process that perform work on the project state provided.
type Worker interface {
	// ProcessActiveProject has a worker perform the work needed to process an active project.
	ProcessActiveProject(ctx context.Context, state *pb.Process, projectName string, project *pb.Process_Project, process *Process) error
	// CleanupProject has a worker perform the work needed to clean up a project that was active previously.
	CleanupProject(ctx context.Context, state *pb.Process, projectName string, process *Process) error
	// Wait indicates that the worker should wait for the next active cycle to begin. Return false to exit worker.
	Wait(ctx context.Context, duration time.Duration) bool
}

// NewProcess creates a new process to perform work of a given name. It will trigger every "scheduleFrequency"
// and workers will report back status updates to the storage layer every "progressFrequency".
//   - If the process is not found in the storage layer, it will initialize with "defaultSettings".
//   - scheduleFrequency may be adjusted to meet schedule frequency constraints.
func NewProcess(name string, worker Worker, store storage.Store, scheduleFrequency time.Duration, defaultSettings *pb.Process_Params) *Process {
	rand.Seed(time.Now().UTC().UnixNano())
	scheduleFrequency, progressFrequency := frequency(scheduleFrequency)
	return &Process{
		name:              name,
		worker:            worker,
		store:             store,
		mutex:             sync.Mutex{},
		scheduleFrequency: scheduleFrequency,
		progressFrequency: progressFrequency,
		defaultSettings:   defaultSettings,
	}
}

// RegisterProject adds a project to the state for workers to process.
func (p *Process) RegisterProject(projectName string, projectParams *pb.Process_Params) (*pb.Process_Project, error) {
	if len(projectName) == 0 {
		return nil, fmt.Errorf("process project registration: cannot register an empty project")
	}
	tx := p.store.LockTx(p.name, 0, nil)
	if tx == nil {
		return nil, fmt.Errorf("lock process registration failed: lock unavailable")
	}
	defer tx.Finish()

	state, err := p.readState(tx)
	if err != nil {
		return nil, err
	}

	now := ptypes.TimestampNow()
	if projectParams == nil {
		projectParams = &pb.Process_Params{}
	}
	proj := &pb.Process_Project{
		Modified: now,
		Params:   projectParams,
		Status:   newStatus(pb.Process_Status_NEW),
	}
	old, ok := state.ActiveProjects[projectName]
	if ok && proto.Equal(old.Params, proj.Params) {
		glog.Infof("process %q instance %q verified project %q was already registered with the same parameters", p.name, instanceID, projectName)
		return proj, nil
	}
	state.ActiveProjects[projectName] = proj
	delete(state.CleanupProjects, projectName)
	delete(state.DroppedProjects, projectName)

	state.SettingsTime = ptypes.TimestampNow()
	if err := p.writeState(state, tx); err != nil {
		return nil, err
	}
	glog.Infof("process %q instance %q registered project %q settings: %+v", p.name, instanceID, projectName, proj.Params)
	return proj, nil
}

// UnregisterProject (eventually) removes a project from the active state, and allows cleanup work to be performed.
func (p *Process) UnregisterProject(projectName string) error {
	tx := p.store.LockTx(p.name, 0, nil)
	if tx == nil {
		return fmt.Errorf("lock process registration failed: lock unavailable")
	}
	defer tx.Finish()

	state, err := p.readState(tx)
	if err != nil {
		return err
	}

	_, dropped := state.DroppedProjects[projectName]
	_, cleanup := state.CleanupProjects[projectName]
	if dropped || cleanup {
		return nil
	}
	// Schedule for cleanup.
	delete(state.ActiveProjects, projectName)
	state.CleanupProjects[projectName] = ptypes.TimestampNow()
	state.SettingsTime = ptypes.TimestampNow()
	if err := p.writeState(state, tx); err != nil {
		return err
	}
	glog.Infof("process %s instance %q scheduling: project %q scheduled for clean up", p.name, instanceID, projectName)
	return nil
}

// UpdateSettings alters resource management settings.
func (p *Process) UpdateSettings(scheduleFrequency time.Duration, settings *pb.Process_Params) error {
	p.defaultSettings = settings

	tx := p.store.LockTx(p.name, 0, nil)
	if tx == nil {
		return fmt.Errorf("lock process to update settings failed: lock unavailable")
	}
	defer tx.Finish()

	state, err := p.readState(tx)
	if err != nil {
		return err
	}

	state.Settings = settings
	state.SettingsTime = ptypes.TimestampNow()
	if scheduleFrequency > 0 {
		scheduleFrequency, progressFrequency := frequency(scheduleFrequency)
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

// Run schedules a background process. Typically this will be on its own go routine.
func (p *Process) Run(ctx context.Context) {
	freq := time.Minute
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

// AddError will add error state to a given status block. Set "projectStatus" to nil if
// it is not specific.
func (p *Process) AddError(err error, projectStatus *pb.Process_Status, state *pb.Process) ErrorAction {
	now := ptypes.TimestampNow()
	action := Continue
	if projectStatus != nil {
		projectStatus.TotalErrors++
		projectStatus.LastErrorTime = now
		if len(projectStatus.Errors) < maxProjectErrors {
			projectStatus.Errors = append(projectStatus.Errors, &pb.Process_Error{Time: now, Text: err.Error()})
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

// AddProjectError will add error state to a given project status block as well as the process status block.
func (p *Process) AddProjectError(err error, project string, state *pb.Process) ErrorAction {
	proj, ok := state.ActiveProjects[project]
	if ok {
		return p.AddError(err, proj.Status, state)
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

// AddProjectStats will increment metrics of a given name within the project and process status.
func (p *Process) AddProjectStats(count float64, name, project string, state *pb.Process) {
	proj, ok := state.ActiveProjects[project]
	if ok {
		proj.Status.Stats[name] = proj.Status.Stats[name] + count
	}
	p.AddStats(count, "project."+name, state)
}

func (p *Process) work(ctx context.Context, state *pb.Process) (Progress, error) {
	// Create stable lists that will be followed even if a merge occurs during
	// any Progress() updates.
	var projects []string
	var cleanup []string
	var drop []string
	for project := range state.ActiveProjects {
		projects = append(projects, project)
	}
	for project := range state.CleanupProjects {
		cleanup = append(cleanup, project)
	}
	// Process in a consistent order makes progress reports easier to compare.
	sort.Strings(projects)
	sort.Strings(cleanup)

	// Process active projects.
	for _, projectName := range projects {
		project, ok := state.ActiveProjects[projectName]
		if !ok {
			// Was removed on merge.
			continue
		}
		p.AddStats(1, "projects", state)
		project.Status = newStatus(pb.Process_Status_ACTIVE)
		err := p.worker.ProcessActiveProject(ctx, state, projectName, project, p)
		if err == nil {
			p.setProjectState(pb.Process_Status_COMPLETED, projectName, state)
		} else if p.AddProjectError(err, projectName, state) == Abort {
			p.setProjectState(pb.Process_Status_ABORTED, projectName, state)
			return Aborted, err
		} else {
			p.setProjectState(pb.Process_Status_INCOMPLETE, projectName, state)
		}
		progress, err := p.Progress(state)
		if progress == Conflict || progress == Aborted {
			return progress, err
		}
	}

	// Process cleanup projects.
	for _, projectName := range cleanup {
		if _, ok := state.CleanupProjects[projectName]; !ok {
			// Was removed on merge.
			continue
		}
		errors := 0
		run := Continue
		err := p.worker.CleanupProject(ctx, state, projectName, p)
		if err != nil && !ignoreCleanupError(err) {
			errors++
			err = fmt.Errorf("warehouse get service accounts on project %q: %v", projectName, err)
			run = p.AddError(err, nil, state)
		}
		if run == Abort {
			p.AddStats(1, "projectsDirty", state)
			p.AddStats(1, "projectsAborted", state)
			return Aborted, err
		}
		if errors == 0 {
			p.AddStats(1, "projectsCleaned", state)
			if _, ok := state.ActiveProjects[projectName]; !ok {
				// Only add to the drop list because there were no errors to retry later and merge has not returned the project to the active list.
				drop = append(drop, projectName)
			}
		} else {
			p.AddStats(1, "projectsDirty", state)
		}
		progress, err := p.Progress(state)
		if progress == Conflict || progress == Aborted {
			return progress, err
		}
	}

	// Move cleanup projects to dropped projects if no errors encountered during cleaning (i.e. it is on the drop list).
	now := ptypes.TimestampNow()
	for _, projectName := range drop {
		delete(state.CleanupProjects, projectName)
		if _, ok := state.ActiveProjects[projectName]; ok {
			// Was added on merge, do not drop.
			continue
		}
		state.DroppedProjects[projectName] = now
	}
	return Completed, nil
}

func (p *Process) setProjectState(statusState pb.Process_Status_State, projectName string, state *pb.Process) {
	project, ok := state.ActiveProjects[projectName]
	if !ok {
		return
	}
	project.Status.State = statusState
	if statusState == pb.Process_Status_COMPLETED {
		project.Status.FinishTime = ptypes.TimestampNow()
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

func (p *Process) start() (*pb.Process, time.Duration, error) {
	tx := p.store.LockTx(p.name, 0, nil)
	if tx == nil {
		return nil, 0, nil
	}
	defer tx.Finish()

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

func (p *Process) update(state *pb.Process) (Progress, error) {
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
	defer tx.Finish()

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
	if _, ok := state.ProcessStatus.Stats["projects"]; !ok {
		p.AddStats(0, "projects", state)
	}
	aggregateStats(state)
	p.update(state)
}

func (p *Process) mergeProcessState(state, src *pb.Process) Progress {
	var rm []string
	now := ptypes.TimestampNow()

	// ActiveProjects: take params etc from src, but retain some processing state.
	// Remove from ActiveProjects if project is not in src.
	for k, destv := range state.ActiveProjects {
		if srcp, ok := src.ActiveProjects[k]; ok {
			srcp.Status = destv.Status
			state.ActiveProjects[k] = srcp
		} else {
			rm = append(rm, k)
		}
	}
	for _, k := range rm {
		delete(state.ActiveProjects, k)
		if _, ok := state.CleanupProjects[k]; !ok {
			state.CleanupProjects[k] = now
		}
	}
	// Copy over active projects from src that are not currently in processing state.
	for k, srcv := range src.ActiveProjects {
		if _, ok := state.ActiveProjects[k]; !ok {
			state.ActiveProjects[k] = srcv
		}
	}

	// CleanupProjects: add all from src.
	for k, v := range src.CleanupProjects {
		state.CleanupProjects[k] = v
		if _, ok := state.DroppedProjects[k]; ok {
			delete(state.DroppedProjects, k)
		}
		if _, ok := state.ActiveProjects[k]; ok {
			delete(state.CleanupProjects, k)
		}
	}

	// DroppedProjects: will only have changed in some error states, add from src
	// if not on other lists. Timestamp of when dropped is not critical.
	for k, v := range src.DroppedProjects {
		_, active := state.ActiveProjects[k]
		_, clean := state.CleanupProjects[k]
		_, drop := state.DroppedProjects[k]
		if !active && !clean && !drop {
			state.CleanupProjects[k] = v
		}
	}
	rm = []string{}
	for k := range state.DroppedProjects {
		_, active := state.ActiveProjects[k]
		_, clean := state.CleanupProjects[k]
		if active || clean {
			rm = append(rm, k)
		}
	}
	for _, project := range rm {
		delete(state.DroppedProjects, project)
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
	now := common.GetNowInUnix()

	d, err := ptypes.Duration(state.ScheduleFrequency)
	if err != nil {
		d = time.Hour
	}
	freq := int64(d.Seconds())
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
	if state.ActiveProjects == nil {
		state.ActiveProjects = make(map[string]*pb.Process_Project)
	}
	if state.CleanupProjects == nil {
		state.CleanupProjects = make(map[string]*tspb.Timestamp)
	}
	if state.DroppedProjects == nil {
		state.DroppedProjects = make(map[string]*tspb.Timestamp)
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
	if secs == 0 {
		return freq
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Calculate the duration until the next start cycle should begin, then add some jitter.
	now := common.GetNowInUnix()
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

func frequency(scheduleFrequency time.Duration) (time.Duration, time.Duration) {
	// Adjust processFrequency and progressFrequency such that:
	// 1. Workers do not fire too often, causing timing errors.
	// 2. Progress occurs frequently enough that lock ownership remains in place with occasional update() errors.
	minScheduleFrequency := 15 * time.Minute
	if scheduleFrequency < minScheduleFrequency {
		scheduleFrequency = minScheduleFrequency
	}
	maxProgressFrequency := minScheduleFrequency / 3
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
