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

package common

import (
	"testing"
)

func TestTimestampString(t *testing.T) {
	epoch := int64(1575344507)
	epochstr := "2019-12-03T03:41:47Z"
	got := TimestampString(epoch)
	if got != epochstr {
		t.Errorf("TimestampString(%d) = %q, want %q", epoch, got, epochstr)
	}
}
