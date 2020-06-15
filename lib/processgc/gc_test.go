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

package processgc

import (
	"context"
	"testing"
	"time"

	glog "github.com/golang/glog" /* copybara-comment */
	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds" /* copybara-comment: clouds */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/process/v1" /* copybara-comment: go_proto */
)

func TestKeyGC(t *testing.T) {
	store := storage.NewMemoryStorage("dam", "testdata/config")
	accounts := []*clouds.Account{
		{ID: "frank@example.org", DisplayName: "ic_123|ic-staging.my-project.appspot.com"},
		{ID: "mary@example.org", DisplayName: "Mary Poppins"},
		{ID: "yvonne@example.org", DisplayName: "ic_456|ic-staging.my-project.appspot.com"},
	}
	wh := clouds.NewMockAccountManager(accounts)
	processName := "gcp_keys"
	gc := NewKeyGC(processName, wh, store, 10*time.Second, 10, func(sa *clouds.Account) bool {
		return sa.ID != "mary@example.org"
	})
	if err := gc.process.UpdateFlowControl(500*time.Millisecond, 100*time.Millisecond); err != nil {
		t.Fatalf("UpdateFlowControl(_,_) failed: %v", err)
	}
	waits := 0
	gc.WaitCondition(func(ctx context.Context, duration time.Duration) bool {
		waits++
		if waits > 1 {
			return false
		}
		return true
	})
	params := &pb.Process_Params{
		IntParams: map[string]int64{
			"foo": 1,
			"bar": 2,
		},
	}
	if _, err := gc.RegisterWork("test_process", params, nil); err != nil {
		t.Fatalf(`RegisterWork("test_process", %+v) failed: %v`, params, err)
	}
	if _, err := gc.RegisterWork("bad", nil, nil); err != nil {
		t.Fatalf(`RegisterWork("bad", nil) failed: %v`, err)
	}
	if err := gc.UnregisterWork("bad", nil); err != nil {
		t.Fatalf(`UnregisterWork("bad") failed: %v`, err)
	}

	gc.Run(context.Background())

	state := &pb.Process{}
	if err := store.Read(storage.ProcessDataType, storage.DefaultRealm, storage.DefaultUser, processName, storage.LatestRev, state); err != nil {
		t.Fatalf(`Read(_, _, _, %q, _, _) failed: %v`, processName, err)
	}

	// Normalize for easy compare.
	gotStatus := state.ProcessStatus
	if gotStatus.Stats["duration"] > 0 {
		gotStatus.Stats["duration"] = 100
	}
	wantStats := map[string]float64{
		"duration":             100,
		"errors":               0,
		"runs":                 1,
		"state.completed":      1,
		"work.accounts":        2,
		"work.accountsRemoved": 2,
		"work.keysKept":        2,
		"work.keysRemoved":     4,
		"workItems":            1,
		"workItemsCleaned":     1,
	}
	glog.Infof("process status: %+v", state.ProcessStatus)
	if diff := cmp.Diff(wantStats, gotStatus.Stats); diff != "" {
		t.Errorf("process status match failed -want +got:\n%s", diff)
	}
	wantState := pb.Process_Status_COMPLETED
	if gotStatus.State != wantState {
		t.Errorf("process status state failed: got %q, want %q", gotStatus.State, wantState)
	}
}

func TestKeyGC_UpdateSettings(t *testing.T) {
	store := storage.NewMemoryStorage("dam", "testdata/config")
	wh := clouds.NewMockAccountManager([]*clouds.Account{})
	processName := "gcp_keys"
	gc := NewKeyGC(processName, wh, store, 10*time.Hour, 10, func(sa *clouds.Account) bool {
		return true
	})
	if err := gc.process.UpdateFlowControl(500*time.Millisecond, 100*time.Millisecond); err != nil {
		t.Fatalf("UpdateFlowControl(_,_) failed: %v", err)
	}

	initFreq := time.Hour
	if initFreq != gc.process.ScheduleFrequency() {
		t.Errorf("process scheduleFrequency mismatch: want %v, got %v", initFreq, gc.process.ScheduleFrequency())
	}

	gc.UpdateSettings(100*time.Hour, 6, nil)

	want := &pb.Process_Params{
		IntParams: map[string]int64{"keyTtl": 420001, "keysPerAccount": 6, "maxRequestedTtl": 360000},
	}
	if !proto.Equal(want, gc.process.DefaultSettings()) {
		t.Errorf("process settings mismatch: want %+v, got %+v", want, gc.process.DefaultSettings())
	}
	wantFreq, _ := time.ParseDuration("11h40m0.1s")
	if wantFreq != gc.process.ScheduleFrequency() {
		t.Errorf("process scheduleFrequency mismatch: want %v, got %v", wantFreq, gc.process.ScheduleFrequency())
	}
}
