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

package process

import (
	"context"
	"sort"
	"testing"
	"time"

	glog "github.com/golang/glog" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
	"github.com/golang/protobuf/ptypes" /* copybara-comment */
	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/process/v1" /* copybara-comment: go_proto */
)

const (
	testProcessName = "gckeys"
)

type mockWorker struct {
	activeProjects  []string
	cleanupProjects []string
	waits           int
}

func (m *mockWorker) ProcessActiveProject(ctx context.Context, state *pb.Process, projectName string, project *pb.Process_Project, process *Process) error {
	glog.Infof("mockWorker processing active project %q", projectName)
	m.activeProjects = append(m.activeProjects, projectName)
	return nil
}

func (m *mockWorker) CleanupProject(ctx context.Context, state *pb.Process, projectName string, process *Process) error {
	glog.Infof("mockWorker cleanup project %q", projectName)
	m.cleanupProjects = append(m.cleanupProjects, projectName)
	return nil
}

func (m *mockWorker) Wait(ctx context.Context, duration time.Duration) bool {
	m.waits++
	if m.waits > 1 {
		glog.Infof("mockWorker exiting")
		return false
	}
	return true
}

func TestProcess(t *testing.T) {
	mock := &mockWorker{}
	store := storage.NewMemoryStorage("dam", "testdata/config")
	process := NewProcess(testProcessName, mock, store, 0, nil)
	if err := process.UpdateFlowControl(500*time.Millisecond, 100*time.Millisecond); err != nil {
		t.Fatalf("UpdateFlowControl(_,_) failed: %v", err)
	}
	params := &pb.Process_Params{
		IntParams: map[string]int64{
			"foo": 1,
			"bar": 2,
		},
	}
	if _, err := process.RegisterProject("test_process", params, nil); err != nil {
		t.Fatalf(`RegisterProject("test_process", %+v) failed: %v`, params, err)
	}
	if _, err := process.RegisterProject("sunset", nil, nil); err != nil {
		t.Fatalf(`RegisterProject("sunset", nil, nil) failed: %v`, err)
	}
	if err := process.UnregisterProject("sunset", nil); err != nil {
		t.Fatalf(`UnregisterProject("sunset", nil) failed: %v`, err)
	}

	process.Run(context.Background())

	sort.Strings(mock.activeProjects)
	if diff := cmp.Diff([]string{"test-project", "test_process"}, mock.activeProjects); diff != "" {
		t.Errorf("process active projects match failed (-want +got):\n%s", diff)
	}

	sort.Strings(mock.cleanupProjects)
	if diff := cmp.Diff([]string{"sunset"}, mock.cleanupProjects); diff != "" {
		t.Errorf("process active projects match failed (-want +got):\n%s", diff)
	}

	state := &pb.Process{}
	if err := store.Read(storage.ProcessDataType, storage.DefaultRealm, storage.DefaultUser, testProcessName, storage.LatestRev, state); err != nil {
		t.Fatalf(`Read(_, _, _, %q, _, _) failed: %v`, testProcessName, err)
	}

	dropped := []string{}
	for k := range state.DroppedProjects {
		dropped = append(dropped, k)
	}
	sort.Strings(dropped)
	if diff := cmp.Diff([]string{"sunset"}, dropped); diff != "" {
		t.Errorf("process dropped projects match failed (-want +got):\n%s", diff)
	}

	// Normalize for easy compare.
	gotStatus := state.ProcessStatus
	if gotStatus.Stats["duration"] > 0 {
		gotStatus.Stats["duration"] = 100
	}
	wantStats := map[string]float64{
		"duration":        100,
		"errors":          0,
		"projects":        2,
		"projectsCleaned": 1,
		"runs":            1,
		"state.completed": 1,
	}
	glog.Infof("process status: %+v", state.ProcessStatus)
	if diff := cmp.Diff(wantStats, gotStatus.Stats); diff != "" {
		t.Errorf("process status match failed -want +got:\n%s", diff)
	}
	wantState := pb.Process_Status_COMPLETED
	if gotStatus.State != wantState {
		t.Errorf("process status state failed: got %q, want %q", gotStatus.State, wantState)
	}

	// Normalize aggregates
	if state.AggregateStats["duration"] > 0 {
		state.AggregateStats["duration"] = 5000
	}
	// New stats added to aggregates found in testdata "process_master_<testProcessName>_latest.json".
	wantAggr := map[string]float64{
		"duration":                5000,
		"errors":                  10,
		"project.accounts":        200,
		"project.accountsRemoved": 45,
		"project.keysKept":        113,
		"project.keysRemoved":     2003,
		"projects":                5,
		"projectsCleaned":         2,
		"runs":                    994,
		"state.aborted":           1,
		"state.completed":         991,
		"state.incomplete":        2,
	}
	if diff := cmp.Diff(wantAggr, state.AggregateStats); diff != "" {
		t.Errorf("process status match failed -want +got:\n%s", diff)
	}
}

type mockMergeWorker struct {
	activeProjects  []string
	cleanupProjects []string
	waits           int
	store           storage.Store
}

func (m *mockMergeWorker) ProcessActiveProject(ctx context.Context, state *pb.Process, projectName string, project *pb.Process_Project, process *Process) error {
	glog.Infof("mockWorker processing active project %q", projectName)
	m.activeProjects = append(m.activeProjects, projectName)
	process.RegisterProject("new_project", nil, nil)
	process.UnregisterProject("test-project", nil)
	return nil
}

func (m *mockMergeWorker) CleanupProject(ctx context.Context, state *pb.Process, projectName string, process *Process) error {
	glog.Infof("mockWorker cleanup project %q", projectName)
	m.cleanupProjects = append(m.cleanupProjects, projectName)
	process.RegisterProject("promote", nil, nil)
	process.UnregisterProject("test_process", nil)
	return nil
}

func (m *mockMergeWorker) Wait(ctx context.Context, duration time.Duration) bool {
	m.waits++
	if m.waits > 1 {
		glog.Infof("mockWorker exiting")
		return false
	}
	return true
}

func TestProcess_Merge(t *testing.T) {
	store := storage.NewMemoryStorage("dam", "testdata/config")
	mock := &mockMergeWorker{store: store}
	process := NewProcess(testProcessName, mock, store, 0, nil)
	if err := process.UpdateFlowControl(500*time.Millisecond, 100*time.Millisecond); err != nil {
		t.Fatalf("UpdateFlowControl(_,_) failed: %v", err)
	}
	process.progressFrequency = -time.Second // force updates and possible merged on every work item
	params := &pb.Process_Params{
		IntParams: map[string]int64{
			"foo": 1,
			"bar": 2,
		},
	}
	// Add and remove projects to populate active ("test-project", "test_process") and cleanup (unregister list).
	register := []string{"promote", "sunset", "test-project", "test_process"}
	unregister := []string{"cleanup_only", "promote", "sunset"}

	for _, project := range register {
		if _, err := process.RegisterProject(project, params, nil); err != nil {
			t.Fatalf(`RegisterProject(%q, %+v) failed: %v`, project, params, err)
		}
	}
	for _, project := range unregister {
		if err := process.UnregisterProject(project, nil); err != nil {
			t.Fatalf(`UnregisterProject(%q, nil) failed: %v`, project, err)
		}
	}

	process.Run(context.Background())

	// Check that we processed the state as it appeared at the start of the run.
	sort.Strings(mock.activeProjects)
	if diff := cmp.Diff([]string{"test-project", "test_process"}, mock.activeProjects); diff != "" {
		t.Errorf("process active projects match failed (-want +got):\n%s", diff)
	}

	sort.Strings(mock.cleanupProjects)
	if diff := cmp.Diff([]string{"cleanup_only", "promote", "sunset"}, mock.cleanupProjects); diff != "" {
		t.Errorf("process cleanup projects match failed (-want +got):\n%s", diff)
	}

	// Check that the existing state in storage reflects the setting changes performed during the run via the mock:
	// 1. "new_project" added to active list.
	// 2. "test-project" moved to cleanup list.
	// ===> MERGE
	// 3. "promote" project was promoted to active list.
	// 4. "test_process" moved to cleanup list.
	// ===> MERGE
	// Note: a given project should only appear on one list at a time.
	state := &pb.Process{}
	if err := store.Read(storage.ProcessDataType, storage.DefaultRealm, storage.DefaultUser, testProcessName, storage.LatestRev, state); err != nil {
		t.Fatalf(`Read(_, _, _, %q, _, _) failed: %v`, testProcessName, err)
	}

	active := []string{}
	for k := range state.ActiveProjects {
		active = append(active, k)
	}
	sort.Strings(active)
	if diff := cmp.Diff([]string{"new_project", "promote"}, active); diff != "" {
		t.Errorf("process active projects match failed (-want +got):\n%s", diff)
	}

	cleanup := []string{}
	for k := range state.CleanupProjects {
		cleanup = append(cleanup, k)
	}
	sort.Strings(cleanup)
	if diff := cmp.Diff([]string{"test-project", "test_process"}, cleanup); diff != "" {
		t.Errorf("process cleanup projects match failed (-want +got):\n%s", diff)
	}

	dropped := []string{}
	for k := range state.DroppedProjects {
		dropped = append(dropped, k)
	}
	sort.Strings(dropped)
	if diff := cmp.Diff([]string{"cleanup_only", "sunset"}, dropped); diff != "" {
		t.Errorf("process dropped projects match failed (-want +got):\n%s", diff)
	}
}

func TestProcess_Conflict(t *testing.T) {
	store := storage.NewMemoryStorage("dam", "testdata/config")
	mock := &mockWorker{}
	process := NewProcess(testProcessName, mock, store, 0, nil)
	if err := process.UpdateFlowControl(500*time.Millisecond, 100*time.Millisecond); err != nil {
		t.Fatalf("UpdateFlowControl(_,_) failed: %v", err)
	}

	state := &pb.Process{}
	if err := store.Read(storage.ProcessDataType, storage.DefaultRealm, storage.DefaultUser, testProcessName, storage.LatestRev, state); err != nil {
		t.Fatalf(`Read(_, _, _, %q, _, _) failed: %v`, testProcessName, err)
	}

	state.Instance = "foo"
	progress, err := process.update(state)
	if progress != Conflict {
		t.Errorf("update(state) returned unexpected progress: want %q, got %q", Conflict, progress)
	}
	if err == nil {
		t.Errorf("update(state) returned unexpected success: conflict expected with an error")
	}
}

func TestProcess_UpdateSettings(t *testing.T) {
	store := storage.NewMemoryStorage("dam", "testdata/config")
	mock := &mockWorker{}
	initFreq := 3 * time.Hour
	updateFreq := 5 * time.Hour
	initSettings := &pb.Process_Params{
		IntParams:    map[string]int64{"a": 1},
		StringParams: map[string]string{"foo": "bar"},
	}
	updateSettings := &pb.Process_Params{
		IntParams:    map[string]int64{"a": 1, "b": 2},
		StringParams: map[string]string{"hello": "world"},
	}
	process := NewProcess(testProcessName, mock, store, initFreq, initSettings)
	if err := process.UpdateFlowControl(500*time.Millisecond, 100*time.Millisecond); err != nil {
		t.Fatalf("UpdateFlowControl(_,_) failed: %v", err)
	}
	process.RegisterProject("foo", nil, nil)
	process.UpdateSettings(updateFreq, updateSettings, nil)
	process.RegisterProject("bar", nil, nil)

	input := &pb.Process{}
	if err := store.Read(storage.ProcessDataType, storage.DefaultRealm, storage.DefaultUser, testProcessName, storage.LatestRev, input); err != nil {
		t.Fatalf(`Read(_, _, _, %q, _, _) failed: %v`, testProcessName, err)
	}

	inputFreq, err := ptypes.Duration(input.ScheduleFrequency)
	if err != nil {
		t.Errorf("ptypes.Duration(%v) failed: %v", input.ScheduleFrequency, err)
	}
	if updateFreq != inputFreq {
		t.Errorf("scheduleFrequency mismatch: want %v, got %v", updateFreq, inputFreq)
	}
	if !proto.Equal(updateSettings, input.Settings) {
		t.Errorf("process settings mismatch: want %+v, got %+v", updateSettings, input.Settings)
	}
}

func TestProcess_UpdateFlowControl(t *testing.T) {
	store := storage.NewMemoryStorage("dam", "testdata/config")
	mock := &mockWorker{}
	initFreq := 3 * time.Hour
	waitFreq := 500 * time.Millisecond
	scheduleFreq := 100 * time.Millisecond
	process := NewProcess(testProcessName, mock, store, initFreq, &pb.Process_Params{})
	if err := process.UpdateFlowControl(waitFreq, scheduleFreq); err != nil {
		t.Fatalf("UpdateFlowControl(%v,%v) failed: %v", waitFreq, scheduleFreq, err)
	}
	if process.initialWaitDuration != waitFreq {
		t.Errorf("initWaitDuration mismatch, got %v, want %v", process.initialWaitDuration, waitFreq)
	}
	if process.minScheduleFrequency != scheduleFreq {
		t.Errorf("minScheduleFrequency mismatch, got %v, want %v", process.minScheduleFrequency, scheduleFreq)
	}
}
