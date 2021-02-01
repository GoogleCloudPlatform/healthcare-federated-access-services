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

// Package globalflags contains global flags of binary, eg. Experimental.
package globalflags

import (
	"os"

	glog "github.com/golang/glog" /* copybara-comment */
)

var (
	// Experimental is a global flag determining if experimental features should be enabled.
	// Set from env var: `export FEDERATED_ACCESS_ENABLE_EXPERIMENTAL=true`
	Experimental = os.Getenv("FEDERATED_ACCESS_ENABLE_EXPERIMENTAL") == "true"

	// DisableAuditLog is a global flag determining if you want to disable audit log.
	// Set from env var: `export DISABLE_AUDIT_LOG=true` or `export FEDERATED_ACCESS_DISABLE_AUDIT_LOG=true`
	DisableAuditLog = os.Getenv("FEDERATED_ACCESS_DISABLE_AUDIT_LOG") == "true" || os.Getenv("DISABLE_AUDIT_LOG") == "true"

	// EnableDevLog is a global flag determining if you want to enable dev log.
	// Set from env var: `export ENABLE_DEV_LOG=true`
	EnableDevLog = os.Getenv("ENABLE_DEV_LOG") == "true"

	// DisableIAMConditionExpiry is a global flag determining if you want to use IAM condition to manage user IAM expiry.
	// Set from env var: `export DISABLE_IAM_CONDITION_EXPIRY=true`
	DisableIAMConditionExpiry = os.Getenv("DISABLE_IAM_CONDITION_EXPIRY") == "true"

	// EnableAWSAdapter is a global flag determining if you want to use enable management of AWS resources.
	// Set from env var: `export ENABLE_AWS_ADAPTER=true`
	EnableAWSAdapter = os.Getenv("ENABLE_AWS_ADAPTER") == "true"

	// LocalSignerAlgorithm is a global flag determining if you want to sign the JWT with specific algorithm, only supported in persona service and using local signer.
	// It will cause err if given invalid value.
	// Set from env var: `export LOCAL_SIGNER_ALGORITHM=RS384`
	LocalSignerAlgorithm = parseLocalSignerAlgorithm()
)

// SignerAlgorithm of JWT.
type SignerAlgorithm string

const (
	// RS256 used to sign JWT.
	RS256 SignerAlgorithm = "RS256"
	// RS384 used to sign JWT.
	RS384 SignerAlgorithm = "RS384"
)

func parseLocalSignerAlgorithm() SignerAlgorithm {
	s := os.Getenv("LOCAL_SIGNER_ALGORITHM")
	switch s {
	case "":
		return RS256
	case "RS256":
		return RS256
	case "RS384":
		return RS384
	default:
		glog.Fatalf("invalid value of LOCAL_SIGNER_ALGORITHM: %s", s)
	}
	return SignerAlgorithm("")
}
