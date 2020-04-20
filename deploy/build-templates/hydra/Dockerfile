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

FROM golang:1.14.1-buster

WORKDIR /

ARG HYDRA_VERSION=v1.4.2

# Install depends and nginx
RUN export JQ_VERSION=1.5+dfsg-2+b1 && \
    export NGINX_VERSION=1.14.2-2+deb10u1 && \
    apt update && \
    apt install -y jq=${JQ_VERSION} nginx=${NGINX_VERSION}

# Nginx config
RUN rm /etc/nginx/sites-enabled/default

# Install Hydra
RUN git clone https://github.com/ory/hydra.git && \
    cd hydra && \
    git checkout ${HYDRA_VERSION} && \
    go build
