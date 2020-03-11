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

// Package srcutil provides utilities for working with files under go module.
package srcutil

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/golang/protobuf/jsonpb" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
)

var (
	root = moduleRoot()
	_    = os.Getenv
)

// Path returns the path to a file in the repo given its relative path to
// the root of the module.
func Path(path string) string {
	if strings.HasPrefix(path, "/") {
		return path
	}
	return filepath.Join(root, path)
}

// Read reads a file in the repo given its relative path to the root of module.
func Read(path string) ([]byte, error) {
	b, err := ioutil.ReadFile(Path(path))
	if err != nil {
		return nil, err
	}
	return b, nil
}

// LoadFile reads a file in the repo given its relative path to the root of module and returns a string.
func LoadFile(path string) (string, error) {
	b, err := Read(path)
	if err != nil {
		return "", err
	}
	return string(b), err
}

// LoadProto reads a JSON proto message from a file.
func LoadProto(path string, msg proto.Message) error {
	file, err := os.Open(Path(path))
	if err != nil {
		return fmt.Errorf("file %q I/O error: %v", path, err)
	}
	defer file.Close()

	if err := jsonpb.Unmarshal(file, msg); err != nil && err != io.EOF {
		return fmt.Errorf("file %q invalid JSON: %v", path, err)
	}
	return nil
}

func moduleRoot() string {
	projectRoot := os.Getenv("PROJECT_ROOT")
	return projectRoot
}
