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

package httputil

import (
	"bytes"
	"testing"

	dpb "github.com/golang/protobuf/ptypes/duration" /* copybara-comment */
	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */
)

func Test_EncodeJSON(t *testing.T) {
	resp := &dpb.Duration{Seconds: 60}
	b := bytes.NewBuffer(nil)

	if err := EncodeJSON(b, resp); err != nil {
		t.Fatalf("EncodeJSON() failed: %v", err)
	}
	got := b.String()
	want := `{"seconds":60}`
	if got != want {
		t.Fatalf("EncodeJSON() = %v, want %v", got, want)
	}
}

func Test_DecodeJSON(t *testing.T) {
	got := &dpb.Duration{}
	b := bytes.NewBufferString(`{"seconds":60}`)
	if err := DecodeJSON(b, got); err != nil {
		t.Fatalf("DecodeJSON() failed: %v", err)
	}
	want := &dpb.Duration{Seconds: 60}
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("DecodeJSON() returned diff (-want +got):\n%s", diff)
	}
}
