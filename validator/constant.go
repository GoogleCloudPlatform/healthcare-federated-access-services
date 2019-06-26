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

// Package validator contains implementations of the ga4gh.Validator interface.
package validator

import (
	"context"

	ga4gh "github.com/GoogleCloudPlatform/healthcare-federated-access-services"
)

// Constant is a ga4gh.Validator that returns a set success and error value.
type Constant struct {
	OK  bool
	Err error
}

// Validate always returns (c.OK, c.Err).
func (c *Constant) Validate(context.Context, *ga4gh.Identity) (bool, error) {
	return c.OK, c.Err
}
