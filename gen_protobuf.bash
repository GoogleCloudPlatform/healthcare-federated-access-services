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

protoc --go_out=paths=source_relative:. common/models/common.proto
protoc --go_out=paths=source_relative:. ic/api/v1/ic_service.proto
protoc --go_out=paths=source_relative:. builder/builder.proto
protoc --go_out=paths=source_relative:. dam/api/v1/dam_secrets.proto
protoc --go_out=paths=source_relative:. dam/api/v1/dam_service.proto

# Install addlicense: go get -u github.com/google/addlicense
find . -type f -name "*.pb.go" -exec addlicense {} \;
