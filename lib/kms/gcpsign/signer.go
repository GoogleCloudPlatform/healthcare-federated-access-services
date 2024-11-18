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

// Package gcpsign contains a client of GCP Cloud KMS RSA256 asymmetric signing.
package gcpsign

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sort"

	"github.com/cenkalti/backoff" /* copybara-comment */
	"cloud.google.com/go/kms/apiv1" /* copybara-comment */
	"google3/third_party/golang/github_com/go_jose/go_jose/v/v3/jose"
	"google.golang.org/api/iterator" /* copybara-comment: iterator */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/retry" /* copybara-comment: retry */

	rpb "google.golang.org/genproto/googleapis/cloud/kms/v1" /* copybara-comment: resources_go_proto */
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1" /* copybara-comment: service_go_proto */
)

const (
	maxPendingKeyRetries = 5
)

// Client of GCP CloudKMS asymmetric signing service.
// We use CloudKMS to sign JWT and expose RSA public keys in KMS for verify.
type Client struct {
	cryptoKeyID    string
	currentVersion string
	client         *kms.KeyManagementClient
	publicKeys     *jose.JSONWebKeySet
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
			Purpose: rpb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &rpb.CryptoKeyVersionTemplate{
				Algorithm: rpb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
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
	if key.Purpose != rpb.CryptoKey_ASYMMETRIC_SIGN ||
		key.VersionTemplate.Algorithm != rpb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256 {
		return nil, fmt.Errorf("key %q has incorrect purpose %q or algorithm %q", cryptoKeyName(projectID, keyRingLocation, keyRingName, keyName), key.Purpose.String(), key.VersionTemplate.Algorithm.String())
	}

	c := &Client{cryptoKeyID: cryptoKeyName(projectID, keyRingLocation, keyRingName, keyName), client: client}
	if err := c.updateKeys(ctx); err != nil {
		return nil, err
	}

	return c, nil
}

// updateKeys fetches current key version and public keys on KMS and convert to jose.JSONWebKeySet.
func (s *Client) updateKeys(ctx context.Context) error {
	// Get the allowed versions
	var versions []*rpb.CryptoKeyVersion

	f := func() error {
		var err error
		versions, err = s.fetchKeyVersions(ctx)
		return err
	}
	if err := backoff.Retry(f, retry.ExponentialBackoff()); err != nil {
		return err
	}

	// use the latest version as current version.
	s.currentVersion = versions[0].Name

	// Get allow public keys
	s.publicKeys = &jose.JSONWebKeySet{}
	for _, version := range versions {
		getPublickeyReq := &kmspb.GetPublicKeyRequest{
			Name: version.Name,
		}
		pub, err := s.client.GetPublicKey(ctx, getPublickeyReq)
		if err != nil {
			return fmt.Errorf("get public key failed. %q", version.Name)
		}

		id := getKeyID(version.Name)
		block, _ := pem.Decode([]byte(pub.Pem))
		if block == nil {
			return fmt.Errorf("pem.Decode() failed")
		}

		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("ParsePKIXPublicKey() failed: %v", err)
		}

		publicKey, ok := parsed.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("Public key is not rsa public key")
		}

		s.publicKeys.Keys = append(s.publicKeys.Keys, jose.JSONWebKey{
			KeyID:     id,
			Key:       publicKey,
			Algorithm: "RS256",
			Use:       "sig",
		})
	}

	return nil
}

func (s *Client) fetchKeyVersions(ctx context.Context) ([]*rpb.CryptoKeyVersion, error) {
	var versions []*rpb.CryptoKeyVersion
	listKeyVersionReq := &kmspb.ListCryptoKeyVersionsRequest{
		Parent:   s.cryptoKeyID,
		PageSize: 5,
		Filter:   "state=ENABLED",
	}
	it := s.client.ListCryptoKeyVersions(ctx, listKeyVersionReq)
	for {
		version, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to fetch key versions: %v", err)
		}
		versions = append(versions, version)
	}

	if len(versions) == 0 {
		return nil, fmt.Errorf("no key version is available")
	}

	// order by createTime
	sort.Slice(versions, func(i int, j int) bool {
		return versions[i].GenerateTime.Seconds > versions[j].GenerateTime.Seconds
	})

	return versions, nil
}

// getKeyID use sha256 hash the key resource name to protect the resource name.
func getKeyID(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// PublicKeys in KMS.
func (s *Client) PublicKeys() *jose.JSONWebKeySet {
	return s.publicKeys
}

// SignJWT signs the given claims return the jwt string.
func (s *Client) SignJWT(ctx context.Context, claims any, header map[string]string) (string, error) {
	sig := &signer{
		c:   s,
		ctx: ctx,
	}

	key := jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       sig,
	}

	opt := &jose.SignerOptions{}
	opt.WithType("JWT")

	if header == nil {
		header = map[string]string{}
	}
	header["kid"] = getKeyID(s.currentVersion)
	for k, v := range header {
		opt.WithHeader(jose.HeaderKey(k), v)
	}

	signer, err := jose.NewSigner(key, opt)
	if err != nil {
		return "", fmt.Errorf("failed to create signer:" + err.Error())
	}

	b, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	res, err := signer.Sign(b)
	if err != nil {
		return "", err
	}

	return res.CompactSerialize()
}

// signer implements jose.OpaqueSigner interface
type signer struct {
	c   *Client
	ctx context.Context
}

// Public returns the public key of the current signing key.
func (sig *signer) Public() *jose.JSONWebKey {
	return &sig.c.publicKeys.Keys[0]
}

// Algs returns a list of supported signing algorithms.
func (sig *signer) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{jose.RS256}
}

// SignPayload signs a payload with the current signing key using the given
// algorithm.
func (sig *signer) SignPayload(payload []byte, alg jose.SignatureAlgorithm) ([]byte, error) {
	if alg != jose.RS256 {
		return nil, fmt.Errorf("only support RS256")
	}

	h := sha256.New()
	h.Write(payload)
	b := h.Sum(nil)

	res, err := sig.c.client.AsymmetricSign(sig.ctx, &kmspb.AsymmetricSignRequest{
		Name:   sig.c.currentVersion,
		Digest: &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: b}},
	})
	if err != nil {
		return nil, err
	}

	return res.Signature, nil
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
