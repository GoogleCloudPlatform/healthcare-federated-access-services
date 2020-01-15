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

// Package srcutil provides a workaround for locating the files to read.
package srcutil

import (
	"io/ioutil"
	"path/filepath"
)

var (
	// ProjectRoot locates resources of project.
	ProjectRoot = os.Getenv("PROJECT_ROOT")
)

// Path returns the path to a file in the repo given its relative path to
// the root of the repo.
func Path(path string) string {
	return filepath.Join(ProjectRoot, path)
}

// Read reads a file in the repo given its relative path to repo root.
func Read(path string) ([]byte, error) {
	b, err := ioutil.ReadFile(Path(path))
	if err != nil {
		return nil, err
	}
	return b, nil
}
