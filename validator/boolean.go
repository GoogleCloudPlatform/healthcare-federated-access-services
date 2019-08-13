// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package validator

import (
	"context"
	"fmt"

	ga4gh "github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh"
)

// Or is a Validator that succeeds if any of the wrapped validators
// returns true.  Evaluation short-circuits and does not necessarily evaluate
// all wrapped validators.
type Or []Validator

// Validate returns true iff one of the validators that this Or wraps returns
// true.  If any of the invoked validators return an error then an error is
// returned.
func (or Or) Validate(ctx context.Context, identity *ga4gh.Identity) (bool, error) {
	for i, v := range or {
		ok, err := v.Validate(ctx, identity)
		if err != nil {
			return false, fmt.Errorf("nested validator at index %d: %v", i, err)
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// And is a Validator that returns false if any of the wrapped validators
// returns false.  Evaluation short-circuits and does not necessarily evaluate
// all wrapped validators.
type And []Validator

// Validate returns false if any of the wrapped validators return false.  If
// any of the validators returns an error then an error is returned.
func (and And) Validate(ctx context.Context, identity *ga4gh.Identity) (bool, error) {
	for i, v := range and {
		ok, err := v.Validate(ctx, identity)
		if err != nil {
			return false, fmt.Errorf("nested validator at index %d: %v", i, err)
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}
