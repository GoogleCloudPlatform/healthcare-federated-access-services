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

package fakesdl

import (
	"context"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes" /* copybara-comment */
	"cloud.google.com/go/logging" /* copybara-comment: logging */
	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */

	glog "github.com/golang/glog" /* copybara-comment */
	mrpb "google.golang.org/genproto/googleapis/api/monitoredres" /* copybara-comment */
	lspb "google.golang.org/genproto/googleapis/logging/type" /* copybara-comment: log_severity_go_proto */
	lepb "google.golang.org/genproto/googleapis/logging/v2" /* copybara-comment: log_entry_go_proto */
	lpb "google.golang.org/genproto/googleapis/logging/v2" /* copybara-comment: logging_go_proto */
	tspb "github.com/golang/protobuf/ptypes/timestamp" /* copybara-comment */
)

func TestLogger_Write(t *testing.T) {
	ctx := context.Background()
	f, stop := New()
	defer stop()

	msg := "something has happened"
	e := logging.Entry{
		Timestamp: time.Date(2020, time.February, 14, 0, 0, 0, 0, time.UTC),
		Severity:  logging.Error,
		Payload:   msg,
		Labels:    map[string]string{"label-name": "label-value"},
	}
	f.Client.Logger("fake-log-id").LogSync(ctx, e)

	got := f.Server.Logs
	want := []*lpb.WriteLogEntriesRequest{{
		LogName: "projects/fake-project-id/logs/fake-log-id",
		Entries: []*lepb.LogEntry{{
			Payload:   &lepb.LogEntry_TextPayload{TextPayload: msg},
			Timestamp: MustTimestampProto(e.Timestamp),
			Severity:  lspb.LogSeverity_ERROR,
			Labels:    e.Labels,
		}},
	}}

	got[0].Resource = nil
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Fatalf("Logs returned diff (-want +got):\n%s", diff)
	}
}

func MustTimestampProto(t time.Time) *tspb.Timestamp {
	ts, err := ptypes.TimestampProto(t)
	if err != nil {
		glog.Fatalf("ptypes.TimestampProto(%v) failed: %v", t, err)
	}
	return ts
}

var _ = mrpb.MonitoredResource{
	Type:   "project",
	Labels: map[string]string{"project_id": "fake-project-id"},
}
