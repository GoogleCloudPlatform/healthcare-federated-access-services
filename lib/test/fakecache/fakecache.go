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

// Package fakecache includes cache used for testing.
package fakecache

import (
	"testing"

	"google3/third_party/golang/github_com/alicebob/miniredis/v/v2/miniredis"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/cache" /* copybara-comment: cache */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/cache/rediz" /* copybara-comment: rediz */
)

// New creates the cache for testing and and func to get the client of the cache.
func New(t *testing.T) (*miniredis.Miniredis, func() cache.Client) {
	t.Helper()

	r, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run() failed: %v", err)
	}

	p := rediz.NewPool(r.Addr())

	t.Cleanup(func() {
		p.Close()
		r.Close()
	})

	return r, func() cache.Client { return p.Client() }
}
