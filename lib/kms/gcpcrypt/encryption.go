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

// Package gcpcrypt contains a client of GCP Cloud KMS symmetric encryption.
// GCP Cloud KMS symmetric encryption service is an encryption/decryption service
// where keys are stored securely on GCP.
package gcpcrypt

import (
	"context"
	"fmt"

	"cloud.google.com/go/kms/apiv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	rpb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

// Client of GCP CloudKMS symmetric encryption service.
// Sensitive data should be encrypted in database.
// With GCP CloudKMS, we don't need to worry about how to store the key safely.
// This Client wraps CloudKMS client in common interface, developer can easier
// support other KMS.
type Client struct {
	cryptoKeyID string
	client      *kms.KeyManagementClient
}

// New returns Client.
func New(ctx context.Context, projectID, keyRingLocation, keyRingName, keyName string, client *kms.KeyManagementClient) (*Client, error) {
	// Try create key ring.
	createRingReq := &kmspb.CreateKeyRingRequest{
		Parent:    locationName(projectID, keyRingLocation),
		KeyRingId: keyRingName,
	}
	if _, err := client.CreateKeyRing(ctx, createRingReq); err != nil && status.Code(err) != codes.AlreadyExists {
		return nil, fmt.Errorf("client.CreateKeyRing(ctx, %q) failed: %v", ringName(projectID, keyRingLocation, keyRingName), err)
	}

	// Try create key.
	createKeyReq := &kmspb.CreateCryptoKeyRequest{
		Parent:      ringName(projectID, keyRingLocation, keyRingName),
		CryptoKeyId: keyName,
		CryptoKey: &rpb.CryptoKey{
			Purpose: rpb.CryptoKey_ENCRYPT_DECRYPT,
			VersionTemplate: &rpb.CryptoKeyVersionTemplate{
				Algorithm: rpb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
			},
		},
	}
	if _, err := client.CreateCryptoKey(ctx, createKeyReq); err != nil && status.Code(err) != codes.AlreadyExists {
		return nil, fmt.Errorf("client.CreateCryptoKey(ctx, %q) failed: %v", cryptoKeyName(projectID, keyRingLocation, keyRingName, keyName), err)
	}

	// Get key information.
	key, err := client.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: cryptoKeyName(projectID, keyRingLocation, keyRingName, keyName)})
	if err != nil {
		return nil, fmt.Errorf("client.GetCryptoKey(ctx, %q) failed: %v", cryptoKeyName(projectID, keyRingLocation, keyRingName, keyName), err)
	}

	// Ensure key is use for symmetric encryption and use correct algorithm.
	if key.Purpose != rpb.CryptoKey_ENCRYPT_DECRYPT ||
		key.VersionTemplate.Algorithm != rpb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION {
		return nil, fmt.Errorf("key %q has incorrect purpose %q or algorithm %q", cryptoKeyName(projectID, keyRingLocation, keyRingName, keyName), key.Purpose.String(), key.VersionTemplate.Algorithm.String())
	}

	return &Client{cryptoKeyID: cryptoKeyName(projectID, keyRingLocation, keyRingName, keyName), client: client}, nil
}

// Encrypt data with Cloud KMS.
func (s *Client) Encrypt(ctx context.Context, data []byte, additionalAuthData string) ([]byte, error) {
	resp, err := s.client.Encrypt(ctx, &kmspb.EncryptRequest{
		Name:                        s.cryptoKeyID,
		Plaintext:                   data,
		AdditionalAuthenticatedData: []byte(additionalAuthData),
	})
	if err != nil {
		return nil, err
	}

	return resp.Ciphertext, nil
}

// Decrypt data with Cloud KMS.
func (s *Client) Decrypt(ctx context.Context, encrypted []byte, additionalAuthData string) ([]byte, error) {
	resp, err := s.client.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:                        s.cryptoKeyID,
		Ciphertext:                  encrypted,
		AdditionalAuthenticatedData: []byte(additionalAuthData),
	})
	if err != nil {
		return nil, err
	}

	return resp.Plaintext, nil
}

func locationName(proj, loc string) string {
	return "projects/" + proj + "/locations/" + loc
}

func ringName(proj, loc, ring string) string {
	return locationName(proj, loc) + "/keyRings/" + ring
}

func cryptoKeyName(proj, loc, ring, key string) string {
	return ringName(proj, loc, ring) + "/cryptoKeys/" + key
}
