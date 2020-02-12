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

package storage

import (
	"path/filepath"
	"testing"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/srcutil" /* copybara-comment: srcutil */
)

const (
	testConfigPath = "testdata/config"
	damService     = "dam"
	damMinService  = "dam-min"
)

type fsTest struct {
	testName     string
	serviceName  string
	path         string
	expectedPath string
}

func TestPath(t *testing.T) {
	tests := []fsTest{
		{
			testName:     "standard path",
			serviceName:  damService,
			path:         testConfigPath,
			expectedPath: srcutil.Path(filepath.Join(testConfigPath, damService)),
		},
		{
			testName:     "min service path",
			serviceName:  damMinService,
			path:         testConfigPath,
			expectedPath: srcutil.Path(filepath.Join(testConfigPath, damMinService)),
		},
	}

	for _, test := range tests {
		fs := NewFileStorage(test.serviceName, test.path)
		info := fs.Info()
		if info["path"] != test.expectedPath {
			t.Fatalf("test %q bad config path for service %q: want %q, got %q", test.testName, test.serviceName, test.expectedPath, info["path"])
		}
	}
}
