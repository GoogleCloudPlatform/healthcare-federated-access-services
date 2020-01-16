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

FROM gcr.io/${YOUR_PROJECT_ID}/hcls-fa-gae-go-nginx-hydra

COPY deploy/gae-flex/build/nginx.conf /etc/nginx/sites-enabled

# Copy IC and DAM
# TODO: should create separating image for ic and dam.
COPY . /healthcare-federated-access-services
RUN cd /healthcare-federated-access-services && \
    go build ./gcp/ic && \
    go build ./gcp/dam

COPY deploy/gae-flex/build/entrypoint.bash /entrypoint.sh

EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]
