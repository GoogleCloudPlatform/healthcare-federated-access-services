#!/bin/bash

# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

echo "List of proto files:"
find ./proto/ -type f -name "*.proto" -exec echo {} \;

echo "Creating symlink for googleapis/google"
ln -s ../googleapis/google ./google

echo
echo "Generating go packages for proto files"
find ./proto/ -type f -name "*.proto" -exec protoc --go_out=plugins=grpc,paths=source_relative:. {} \;
echo "Generating go packages for proto files: completed"

# Install addlicense: go get -u github.com/google/addlicense
echo "Adding license to go packages"
find ./proto/ -type f -name "*.pb.go" -exec addlicense {} \;
echo "Adding license to go packages: completed"

echo "Removing symlink for googleapis/google"
rm ./google
