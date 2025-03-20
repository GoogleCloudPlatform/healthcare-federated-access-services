// Copyright 2020 Google LLC.
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

// Package kms offers interfaces for providing encryption services and signing services.
package kms

import (
	"context"

	"github.com/go-jose/go-jose/v4" /* copybara-comment */
)

// Encryption abstracts a encryption service for storing encrypted data.
type Encryption interface {
	Encrypt(ctx context.Context, data []byte, additionalAuthData string) ([]byte, error)
	Decrypt(ctx context.Context, encrypted []byte, additionalAuthData string) ([]byte, error)
}

// Signer abstracts a signing service for jwt.
type Signer interface {
	PublicKeys() *jose.JSONWebKeySet
	SignJWT(ctx context.Context, claims any, header map[string]string) (string, error)
}
