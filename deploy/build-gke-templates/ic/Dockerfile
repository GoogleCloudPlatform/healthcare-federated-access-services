# Copyright 2020 Google LLC
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

FROM golang:1.21-bullseye

# Copy IC
COPY . /hcls-fa
RUN cd /hcls-fa && \
    go build ./gcp/ic

COPY deploy/build-gke-templates/ic/entrypoint.bash /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

EXPOSE 8080
