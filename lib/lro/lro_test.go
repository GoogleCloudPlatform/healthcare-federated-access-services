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

package lro

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/scim" /* copybara-comment: scim */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	glog "github.com/golang/glog" /* copybara-comment */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/process/v1" /* copybara-comment: go_proto */
)

func TestLRO(t *testing.T) {
	lroID := "remove_test_realm"
	processName := "lro"
	realm := "test"
	existingAcct := "non-admin@example.org"

	store := storage.NewMemoryStorage("ic-min", "testdata/config")
	lro, err := New(processName, 10*time.Second, 1*time.Second, store, nil)
	if err != nil {
		t.Fatalf("lro.New failed: %v", err)
	}
	if err := lro.process.UpdateFlowControl(500*time.Millisecond, 100*time.Millisecond, 50*time.Millisecond); err != nil {
		t.Fatalf("process.UpdateFlowControl(_,_,_) failed: %v", err)
	}
	waits := 0
	lro.WaitCondition(func(ctx context.Context, duration time.Duration) bool {
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
	identity := &ga4gh.Identity{
		Subject: "subject-1",
		Issuer:  "https://issuer.example.org",
		Email:   "test@example.org",
	}
	if _, err := lro.AddRealmRemoval(lroID, realm, identity, nil); err != nil {
		t.Fatalf(`RegisterWork("test_process", %+v) failed: %v`, params, err)
	}

	gotWork := &pb.Process_Work{}
	if err := store.Read(storage.LongRunningOperationDatatype, storage.DefaultRealm, Active, lroID, storage.LatestRev, gotWork); err != nil {
		t.Fatalf(`before LRO Read(_, _, %q, %q, _, _) failed: %v`, Active, lroID, err)
	}
	wantParts := &pb.Process_Work{
		Params: &pb.Process_Params{
			StringParams: map[string]string{
				"email":     "test@example.org",
				"id":        "remove_test_realm",
				"issuer":    "https://issuer.example.org",
				"label":     `remove realm "test"`,
				"operation": "remove-realm",
				"realm":     "test",
				"subject":   "subject-1",
			},
		},
		Status: &pb.Process_Status{
			State: pb.Process_Status_NEW,
		},
	}
	glog.Infof("params: %+v", gotWork.GetParams())
	if gotWork.Modified != nil {
		// Ignore this timestamp for comparison below.
		gotWork.Modified = nil
	}
	if diff := cmp.Diff(wantParts, gotWork, protocmp.Transform()); diff != "" {
		t.Errorf("work params match failed -want +got:\n%s", diff)
	}

	sam := scim.New(store)
	acct, status, err := sam.LookupAccount(existingAcct, realm, true, nil)
	if err != nil || acct == nil || status != http.StatusOK {
		t.Fatalf("cannot load account %q on realm %q (status %v): %v", existingAcct, realm, status, err)
	}

	lro.Run(context.Background())

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
		"errors":           0,
		"workItemsCleaned": 0,
	}
	glog.Infof("process: %+v", state)
	if diff := cmp.Diff(wantStats, gotStatus.Stats); diff != "" {
		t.Errorf("process status match failed -want +got:\n%s", diff)
	}
	wantState := pb.Process_Status_COMPLETED
	if gotStatus.State != wantState {
		t.Errorf("process status state failed: got %q, want %q", gotStatus.State, wantState)
	}

	if _, status, err = sam.LookupAccount(existingAcct, realm, true, nil); status != http.StatusNotFound || err == nil || !storage.ErrNotFound(err) {
		t.Fatalf("after LRO completion: load status mismatch: want %v, got %v: %v", http.StatusNotFound, status, err)
	}

	// Item should have moved off the "active" queue.
	if err := store.Read(storage.LongRunningOperationDatatype, storage.DefaultRealm, Active, lroID, storage.LatestRev, gotWork); err == nil || !storage.ErrNotFound(err) {
		t.Fatalf(`after LRO Read(_, _, %q, %q, _, _) ACTIVE queue want not found, got: %v`, Active, lroID, err)
	}

	// Item should have moved on the "inactive" queue.
	gotWork.Reset()
	if err := store.Read(storage.LongRunningOperationDatatype, storage.DefaultRealm, Inactive, lroID, storage.LatestRev, gotWork); err != nil {
		t.Fatalf(`after LRO Read(_, _, %q, %q, _, _) INACTIVE list failed: %v`, Inactive, lroID, err)
	}
	glog.Infof("final work state: %+v", gotWork)
	// Ignore timestamps.
	if gotWork.Modified != nil {
		gotWork.Modified = nil
	}
	st := gotWork.GetStatus()
	if st.StartTime != nil {
		st.StartTime = nil
	}
	if st.ProgressTime != nil {
		st.ProgressTime = nil
	}
	if st.FinishTime != nil {
		st.FinishTime = nil
	}
	if st.Stats != nil && st.Stats["duration"] > 0 {
		st.Stats["duration"] = 100
	}
	wantFinal := &pb.Process_Work{
		Params: &pb.Process_Params{
			StringParams: map[string]string{
				"email":     "test@example.org",
				"id":        "remove_test_realm",
				"issuer":    "https://issuer.example.org",
				"label":     `remove realm "test"`,
				"operation": "remove-realm",
				"realm":     "test",
				"subject":   "subject-1",
			},
		},
		Status: &pb.Process_Status{
			State: pb.Process_Status_COMPLETED,
			Stats: map[string]float64{
				"duration":                 100,
				"removeRealm.itemsRemoved": 6,
				"runs":                     1,
				"state.completed":          1,
			},
		},
	}
	if diff := cmp.Diff(wantFinal, gotWork, protocmp.Transform()); diff != "" {
		t.Errorf("work params match failed -want +got:\n%s", diff)
	}

	if err = lro.Remove(lroID, nil); err != nil {
		t.Errorf("Remove(%q) failed: %v", lroID, err)
	}
	// Read after deleted to fail to find it.
	if err := store.Read(storage.LongRunningOperationDatatype, storage.DefaultRealm, Inactive, lroID, storage.LatestRev, gotWork); err == nil || !storage.ErrNotFound(err) {
		t.Fatalf(`after Removed Read(_, _, %q, %q, _, _) INACTIVE expected not found, got: %v`, Inactive, lroID, err)
	}
}
