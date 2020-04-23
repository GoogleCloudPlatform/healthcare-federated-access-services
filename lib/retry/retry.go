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

// Package retry includes config for backoff
package retry

import (
	"time"

	"github.com/cenkalti/backoff" /* copybara-comment */
)

const (
	backoffInitialInterval     = 1 * time.Second
	backoffRandomizationFactor = 0.5
	backoffMultiplier          = 1.5
	backoffMaxInterval         = 3 * time.Second
	backoffMaxElapsedTime      = 10 * time.Second
)

// ExponentialBackoff returns a new backoff ExponentialBackoff
func ExponentialBackoff() *backoff.ExponentialBackOff {
	return &backoff.ExponentialBackOff{
		InitialInterval:     backoffInitialInterval,
		RandomizationFactor: backoffRandomizationFactor,
		Multiplier:          backoffMultiplier,
		MaxInterval:         backoffMaxInterval,
		MaxElapsedTime:      backoffMaxElapsedTime,
		Clock:               backoff.SystemClock,
	}
}
