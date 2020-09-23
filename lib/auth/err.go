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

package auth

type errType = string

const (
	errClientIDMissing           errType = "setup:missing_client_id_to_verify"
	errFetchClientSecretsMissing errType = "setup:missing_fetchClientSecrets"
	errBodyTooLarge              errType = "req:body_too_large"
	errClientUnavailable         errType = "client:unavailable"
	errClientMissing             errType = "client:missing"
	errClientInvalid             errType = "client:invalid"
	errSecretMismatch            errType = "client:secret_mismatch"
	errTokenInvalid              errType = "token:invalid"
	errScopeMissing              errType = "id:scope_missing"
	errIDVerifyFailed            errType = "id:verify_failed"
	errCheckAdminFailed          errType = "id:check_admin_failed"
	errCacheDecodeFailed         errType = "cache:decode_json_failed"
	errCacheEncodeFailed         errType = "cache:encode_json_failed"
	errNotAdmin                  errType = "role:user_not_admin"
	errUserMismatch              errType = "role:user_mismatch"
	errUnknownRole               errType = "role:unknown_role"
)
