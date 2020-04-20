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

package httputils

import (
	"fmt"
	"html/template"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/srcutil" /* copybara-comment: srcutil */
)

// TemplateFromFiles constructs the html safe template from given file.
// name: name of temaplate.
// path: path of the template file.
func TemplateFromFiles(paths ...string) (*template.Template, error) {
	var ps []string
	for _, p := range paths {
		ps = append(ps, srcutil.Path(p))
	}

	t, err := template.ParseFiles(ps...)
	if err != nil {
		return nil, fmt.Errorf("template.ParseFiles() failed: %v", err)
	}

	return t, nil
}
