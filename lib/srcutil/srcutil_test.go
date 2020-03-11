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

package srcutil

import (
	"path/filepath"
	"testing"

	"github.com/golang/protobuf/proto" /* copybara-comment */
	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
)

const testfileContent string = `This is a text file for testing.
`

func TestPath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "",
			want:  root,
		},
		{
			input: "deploy/config",
			want:  filepath.Join(root, "deploy/config"),
		},
		{
			input: "/my/path/from/root",
			want:  "/my/path/from/root",
		},
	}

	for _, tc := range tests {
		if got := Path(tc.input); got != tc.want {
			t.Errorf("Path(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestRead(t *testing.T) {
	path := "lib/srcutil/testfile.txt"
	got, err := Read(path)
	if err != nil {
		t.Fatalf("Read(%v) failed: %v", path, err)
	}

	if want := testfileContent; string(got) != want {
		t.Fatalf("Read(%v) doesn't match the contents of the file.", path)
	}
}

func TestLoadFile(t *testing.T) {
	path := "lib/srcutil/testfile.txt"
	got, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile(%v) failed: %v", path, err)
	}

	if want := testfileContent; got != want {
		t.Fatalf("LoadFile(%v) doesn't match the contents of the file.", path)
	}
}

func TestLoadProto(t *testing.T) {
	path := "lib/srcutil/testproto.json"
	got := &cpb.Descriptor{}
	if err := LoadProto(path, got); err != nil {
		t.Fatalf("LoadProto(%q, _) failed: %v", path, err)
	}
	want := &cpb.Descriptor{
		Label:       "hi",
		Description: "there",
	}
	if !proto.Equal(want, got) {
		t.Errorf("LoadProto(%q, _) mismatch: got %+v, want %+v", path, got, want)
	}
}
