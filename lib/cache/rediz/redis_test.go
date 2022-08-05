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

package rediz

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"google3/third_party/golang/github_com/alicebob/miniredis/v/v2/miniredis"
	"github.com/gomodule/redigo/redis" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/errutil" /* copybara-comment: errutil */
)

func Test_Set(t *testing.T) {
	_, p := setup(t)

	c := p.Client()
	defer c.Close()

	want := []byte("hello")

	if err := c.SetWithExpiry("k", want, 3600); err != nil {
		t.Fatalf("SetWithExpiry() failed: %v", err)
	}

	got, err := c.Get("k")
	if err != nil {
		t.Fatalf("Get() failed: %v", err)
	}

	if d := cmp.Diff(want, got); len(d) > 0 {
		t.Errorf("value (-want, +got): %v", d)
	}

	// ensure the value set with TTL. TTL should > 0
	ttl, err := redis.Int(c.conn.Do("TTL", "k"))
	if err != nil {
		t.Fatalf("TTL failed: %v", err)
	}

	if ttl <= 0 {
		t.Errorf("TTL = %d, wants > 0", ttl)
	}
}

func Test_Get(t *testing.T) {
	r, p := setup(t)

	c := p.Client()

	want := []byte("hello")

	if err := c.SetWithExpiry("key", want, 3600); err != nil {
		t.Fatalf("SetWithExpiry() failed: %v", err)
	}
	if err := c.SetWithExpiry("expired", want, 1); err != nil {
		t.Fatalf("SetWithExpiry() failed: %v", err)
	}
	defer c.Close()

	r.FastForward(2 * time.Second)

	tests := []struct {
		name     string
		key      string
		notFound bool
		want     []byte
	}{
		{
			name: "success",
			key:  "key",
			want: want,
		},
		{
			name:     "not exist",
			key:      "not_exist",
			notFound: true,
			want:     nil,
		},
		{
			name:     "expired",
			key:      "expired",
			notFound: true,
			want:     nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := p.Client()
			defer c.Close()

			got, err := c.Get(tc.key)
			if err != nil {
				if tc.notFound && errutil.NotFound(err) {
				} else {
					t.Fatalf("Get() failed: %v", err)
				}
			}

			if d := cmp.Diff(tc.want, got); len(d) > 0 {
				t.Errorf("Get() (-want, +got): %s", d)
			}
		})
	}
}

func setup(t *testing.T) (*miniredis.Miniredis, *Pool) {
	t.Helper()

	r, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run() failed: %v", err)
	}

	p := NewPool(r.Addr())

	t.Cleanup(func() {
		p.Close()
		r.Close()
	})

	return r, p
}
