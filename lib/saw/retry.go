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

package saw

import (
	"time"

	"github.com/cenkalti/backoff" /* copybara-comment */
	"google.golang.org/api/googleapi" /* copybara-comment: googleapi */
)

const (
	backoffInitialInterval     = 1 * time.Second
	backoffRandomizationFactor = 0.5
	backoffMultiplier          = 1.5
	backoffMaxInterval         = 3 * time.Second
	backoffMaxElapsedTime      = 10 * time.Second
)

var (
	maxAccessTokenTTL  = 1 * time.Hour
)

func exponentialBackoff() *backoff.ExponentialBackOff {
	return &backoff.ExponentialBackOff{
		InitialInterval:     backoffInitialInterval,
		RandomizationFactor: backoffRandomizationFactor,
		Multiplier:          backoffMultiplier,
		MaxInterval:         backoffMaxInterval,
		MaxElapsedTime:      backoffMaxElapsedTime,
		Clock:               backoff.SystemClock,
	}
}

func convertToPermanentErrorIfApplicable(err error, formattedErr error) error {
	if googleErr, ok := err.(*googleapi.Error); ok {
		// This logic follows the guidance at
		// https://cloud.google.com/apis/design/errors#error_retries
		if googleErr.Code == 500 || googleErr.Code == 503 {
			return formattedErr
		}
	}
	// TODO: Extend this function's logic if other types of errors need
	// to be classified as permanent errors vs. retryable errors.
	return backoff.Permanent(formattedErr)
}
