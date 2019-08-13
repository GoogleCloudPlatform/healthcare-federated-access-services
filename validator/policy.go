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

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh"
)

// Policy is a ga4gh.Validator that succeeds if any of the wrapped validators
// returns true.  Evaluation short-circuits and does not necessarily evaluate
// all wrapped validators.
type Policy struct {
	Allow    Validator
	Disallow Validator
}

func NewPolicy(allow Validator, disallow Validator) *Policy {
	return &Policy{
		Allow:    allow,
		Disallow: disallow,
	}
}

// Validate returns true iff:
// 1. the allow clause is absent or it returns true; and
// 2. the disallow is absent or it returns false.
func (r Policy) Validate(ctx context.Context, identity *ga4gh.Identity) (bool, error) {
	if r.Disallow != nil {
		ok, err := r.Disallow.Validate(ctx, identity)
		if err != nil {
			return false, err
		}
		if ok {
			// Disallow is true, so validate is false (i.e. not allowed).
			return false, nil
		}
	}
	if r.Allow != nil {
		return r.Allow.Validate(ctx, identity)
	}
	return true, nil
}
