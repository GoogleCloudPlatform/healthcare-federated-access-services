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

// Package hydraapi contains models generate from https://raw.githubusercontent.com/ory/hydra/master/docs/api.swagger.json
// by github.com/go-swagger/go-swagger. See README.md for details.
package hydraapi

import "fmt"

// Error implements error interface.
func (s *GenericError) Error() string {
	return fmt.Sprintf("Hydra GenericError %d %s: %s", s.Code, *s.Name, s.Description)
}
