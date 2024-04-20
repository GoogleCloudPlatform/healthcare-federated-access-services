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

# Installation steps:
# 1. curl -LO https://github.com/protocolbuffers/protobuf/releases/download/v26.1/protoc-26.1-linux-x86_64.zip
# 2. unzip protoc-26.1-linux-x86_64.zip -d ~/protoc
# 3. go install github.com/google/addlicense@latest
# 4. go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2
# 5. go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28
# 6. PATH=$PATH:$HOME/go/bin:$HOME/protoc/bin

# Usage:
# ./gen_protobuf.bash
# Remove unimplemented method in `proto/tokens/v1/tokens_grpc.pb.go`

echo "List of proto files:"
find ./proto/ -type f -name "*.proto" -exec echo {} \;

echo "Creating symlink for googleapis/google"
ln -s $(p4 --format '%clientRoot%' info)/google3/third_party/golang/gogo/googleapis/google ./google

echo
echo "Generating go packages for proto files"
find ./proto/ -type f -name "*.proto" -exec protoc --go-grpc_out=paths=source_relative:. --go_out=paths=source_relative:. {} \;
echo "Generating go packages for proto files: completed"

# Install addlicense: go get -u github.com/google/addlicense
echo "Adding license to go packages"
find ./proto/ -type f -name "*.pb.go" -exec addlicense {} \;
echo "Adding license to go packages: completed"

echo "Removing symlink for googleapis/google"
rm ./google
