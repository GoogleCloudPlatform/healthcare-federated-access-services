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

package hydra

import (
	"testing"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
)

func TestNormalizeIdentity(t *testing.T) {
	id := &ga4gh.Identity{
		Scp: []string{"aaa", "bbb"},
		Extra: map[string]interface{}{
			"identities": []interface{}{"a@example.com", "b@example.com"},
		},
	}

	want := &ga4gh.Identity{
		Scp: []string{"aaa", "bbb"},
		Extra: map[string]interface{}{
			"identities": []interface{}{"a@example.com", "b@example.com"},
		},
		Scope: "aaa bbb",
		Identities: map[string][]string{
			"a@example.com": nil,
			"b@example.com": nil,
		},
	}

	got := NormalizeIdentity(id)

	if d := cmp.Diff(want, got); len(d) > 0 {
		t.Errorf("NormalizeIdentity() (-want +got): %s", d)
	}
}
