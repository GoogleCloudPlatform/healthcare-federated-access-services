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

// Package cache includes error and interface for cache.
package cache

// Client of cache.
type Client interface {
	// Get a value associated with given key in cache.
	Get(key string) ([]byte, error)
	// SetWithExpiry add a key-value pair with expiry in cache. Expiry in duration second not timestamp.
	SetWithExpiry(key string, value []byte, seconds int64) error
	// Close returns the client after use.
	Close() error
}
