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

package gcpcrypt

import (
	"bytes"
	"context"
	"net"
	"testing"

	"cloud.google.com/go/kms/apiv1" /* copybara-comment */
	"google.golang.org/api/option" /* copybara-comment: option */
	"google.golang.org/grpc" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */

	rpb "google.golang.org/genproto/googleapis/cloud/kms/v1" /* copybara-comment: resources_go_proto */
	kmsgrpc "google.golang.org/genproto/googleapis/cloud/kms/v1" /* copybara-comment: service_go_grpc */
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1" /* copybara-comment: service_go_proto */
)

const (
	project  = "mproj"
	location = "global"
	keyring  = "mring"
	keyname  = "mkey"
)

func setup(t *testing.T) (*kms.KeyManagementClient, *stubKMS) {
	ctx := context.Background()

	stub := &stubKMS{
		createKeyResp:     &rpb.CryptoKey{},
		createKeyRingResp: &rpb.KeyRing{},
		getKeyResp: &rpb.CryptoKey{
			Purpose: rpb.CryptoKey_ENCRYPT_DECRYPT,
			VersionTemplate: &rpb.CryptoKeyVersionTemplate{
				Algorithm: rpb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
			},
		},
	}

	srv := grpc.NewServer()
	kmsgrpc.RegisterKeyManagementServiceServer(srv, stub)
	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(lis)

	conn, err := grpc.Dial(lis.Addr().String(), grpc.WithInsecure())
	if err != nil {
		t.Fatalf("grpc.Dial(lis.Addr().String(), grpc.WithInsecure()) failed: %v", err)
	}

	clientOpt := option.WithGRPCConn(conn)
	// Create the KMS client.
	client, err := kms.NewKeyManagementClient(ctx, clientOpt)
	if err != nil {
		t.Fatalf("NewKeyManagementClient(ctx, clientOpt) failed: %v", err)
	}

	return client, stub
}

func TestClient_EnsureNewClientTryCreateKeyRingAndKey(t *testing.T) {
	client, stub := setup(t)

	_, err := New(context.Background(), project, location, keyring, keyname, client)
	if err != nil {
		t.Fatalf("New(ctx, project, location, keyring, keyname, clientOpt) failed: %q", err)
	}

	if stub.createKeyRingReq == nil || stub.createKeyRingReq.KeyRingId != keyring {
		t.Fatalf("CreateKeyRing calls with %v, wants %v", stub.createKeyRingReq.KeyRingId, keyring)
	}
	if stub.createKeyReq == nil || stub.createKeyReq.CryptoKeyId != keyname {
		t.Fatalf("CreateCryptoKey calls with %v, wants %v", stub.createKeyReq.CryptoKeyId, keyname)
	}
}

func TestClient_EncryptDecrypt(t *testing.T) {
	ctx := context.Background()

	client, stub := setup(t)

	s, err := New(ctx, project, location, keyring, keyname, client)
	if err != nil {
		t.Fatalf("New(ctx, project, location, keyring, keyname, clientOpt) failed: %q", err)
	}

	const additionalAuthData = "aad"
	data := []byte("This is a message.")

	stub.encResp = &kmspb.EncryptResponse{Ciphertext: data}
	ciphertext, err := s.Encrypt(ctx, data, additionalAuthData)
	if err != nil {
		t.Fatalf("s.Encrypt(ctx, data, aad) failed, %s", err)
	}

	stub.decResp = &kmspb.DecryptResponse{Plaintext: data}
	plaintext, err := s.Decrypt(ctx, ciphertext, additionalAuthData)
	if err != nil {
		t.Fatalf("s.DecryptResponse(ctx, ciphertext, aad) failed, %s", err)
	}

	if !bytes.Equal(plaintext, data) {
		t.Fatalf("s.Decrypt(ctx, ciphertext, add) = %v, wants %v", plaintext, data)
	}
}

// stubKMS is a mock KMS server for testing.
type stubKMS struct {
	kmsgrpc.KeyManagementServiceServer

	createKeyRingReq  *kmspb.CreateKeyRingRequest
	createKeyRingResp *rpb.KeyRing
	createKeyRingErr  error

	createKeyReq  *kmspb.CreateCryptoKeyRequest
	createKeyResp *rpb.CryptoKey
	createKeyErr  error

	getKeyReq  *kmspb.GetCryptoKeyRequest
	getKeyResp *rpb.CryptoKey
	getKeyErr  error

	encReq  *kmspb.EncryptRequest
	encResp *kmspb.EncryptResponse
	encErr  error

	decReq  *kmspb.DecryptRequest
	decResp *kmspb.DecryptResponse
	decErr  error
}

func (s *stubKMS) CreateKeyRing(ctx context.Context, req *kmspb.CreateKeyRingRequest) (*rpb.KeyRing, error) {
	s.createKeyRingReq = proto.Clone(req).(*kmspb.CreateKeyRingRequest)
	return proto.Clone(s.createKeyRingResp).(*rpb.KeyRing), s.createKeyRingErr
}
func (s *stubKMS) CreateCryptoKey(ctx context.Context, req *kmspb.CreateCryptoKeyRequest) (*rpb.CryptoKey, error) {
	s.createKeyReq = proto.Clone(req).(*kmspb.CreateCryptoKeyRequest)
	return proto.Clone(s.getKeyResp).(*rpb.CryptoKey), s.createKeyErr
}
func (s *stubKMS) GetCryptoKey(ctx context.Context, req *kmspb.GetCryptoKeyRequest) (*rpb.CryptoKey, error) {
	s.getKeyReq = proto.Clone(req).(*kmspb.GetCryptoKeyRequest)
	return proto.Clone(s.getKeyResp).(*rpb.CryptoKey), s.getKeyErr
}
func (s *stubKMS) Encrypt(ctx context.Context, req *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
	s.encReq = proto.Clone(req).(*kmspb.EncryptRequest)
	return proto.Clone(s.encResp).(*kmspb.EncryptResponse), s.encErr
}
func (s *stubKMS) Decrypt(ctx context.Context, req *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
	s.decReq = proto.Clone(req).(*kmspb.DecryptRequest)
	return proto.Clone(s.decResp).(*kmspb.DecryptResponse), s.decErr
}
