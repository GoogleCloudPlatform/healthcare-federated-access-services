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

package gcpsign

import (
	"context"
	"encoding/base64"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/kms" /* copybara-comment */
	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"github.com/google/go-cmp/cmp/cmpopts" /* copybara-comment */
	"google.golang.org/api/option" /* copybara-comment: option */
	"google.golang.org/grpc" /* copybara-comment */
	"gopkg.in/square/go-jose.v2" /* copybara-comment */
	"gopkg.in/square/go-jose.v2/jwt" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */

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

var (
	versionResName = cryptoKeyName(project, location, keyring, keyname) + "/versions/1"
)

func setup(t *testing.T) (*kms.KeyManagementClient, *stubKMS) {
	ctx := context.Background()

	stub := &stubKMS{
		createKeyResp:     &rpb.CryptoKey{},
		createKeyRingResp: &rpb.KeyRing{},
		getKeyResp: &rpb.CryptoKey{
			Purpose: rpb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &rpb.CryptoKeyVersionTemplate{
				Algorithm: rpb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
			},
		},
		listVerResp: &kmspb.ListCryptoKeyVersionsResponse{
			CryptoKeyVersions: []*rpb.CryptoKeyVersion{
				{
					Name:  versionResName,
					State: rpb.CryptoKeyVersion_ENABLED,
				},
			},
		},
		getPubKeyResp: &rpb.PublicKey{
			Pem: testkeys.Default.PublicStr,
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
		t.Fatalf("New() failed: %q", err)
	}

	if stub.createKeyRingReq == nil || stub.createKeyRingReq.KeyRingId != keyring {
		t.Fatalf("CreateKeyRing calls with %v, wants %v", stub.createKeyRingReq.KeyRingId, keyring)
	}
	if stub.createKeyReq == nil || stub.createKeyReq.CryptoKeyId != keyname {
		t.Fatalf("CreateCryptoKey calls with %v, wants %v", stub.createKeyReq.CryptoKeyId, keyname)
	}
}

func TestClient_PublicKeys(t *testing.T) {
	client, _ := setup(t)

	s, err := New(context.Background(), project, location, keyring, keyname, client)
	if err != nil {
		t.Fatalf("New() failed: %q", err)
	}

	got := s.PublicKeys()
	want := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				KeyID:     getKeyID(versionResName),
				Key:       testkeys.Default.Public,
				Algorithm: "RS256",
				Use:       "sig",
			},
		},
	}

	if d := cmp.Diff(want, got, cmpopts.IgnoreUnexported(big.Int{})); len(d) > 0 {
		t.Errorf("public keys (-want, +got): %s", d)
	}
}

func TestClient_SignJWT(t *testing.T) {
	ctx := context.Background()

	client, stub := setup(t)

	s, err := New(ctx, project, location, keyring, keyname, client)
	if err != nil {
		t.Fatalf("New() failed: %q", err)
	}

	stub.signResp = &kmspb.AsymmetricSignResponse{
		Signature: []byte("sig"),
	}

	iss := "http://iss.example.com"
	clientID := "client-1234"
	sub := "sub-1234"
	claims := jwt.Claims{
		Issuer:   iss,
		Subject:  sub,
		Expiry:   jwt.NewNumericDate(time.Now().Add(10 * time.Hour)),
		Audience: []string{clientID},
	}

	header := map[string]string{
		"jku": "http://iss.example.com/.well-known/jwks",
	}

	rawTok, err := s.SignJWT(ctx, claims, header)
	if err != nil {
		t.Fatalf("s.SignJWT() failed: %v", err)
	}

	ss := strings.Split(rawTok, ".")
	if len(ss) != 3 {
		t.Errorf("jwt format incorrect: %q", rawTok)
	}

	wantSig := base64.StdEncoding.EncodeToString([]byte("sig"))

	if ss[2] != wantSig {
		t.Errorf("jwt sig = %s, wants %s", ss[2], wantSig)
	}

	tok, err := jwt.ParseSigned(rawTok)
	if err != nil {
		t.Fatalf("jwt.ParseSigned() failed: %v", err)
	}

	if len(tok.Headers) != 1 {
		t.Fatalf("len(t.Headers) %d, wants 1", len(tok.Headers))
	}

	wantHeader := jose.Header{
		KeyID:     getKeyID(versionResName),
		Algorithm: "RS256",
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"jku": "http://iss.example.com/.well-known/jwks",
			"typ": "JWT",
		},
	}

	if d := cmp.Diff(wantHeader, tok.Headers[0], cmpopts.IgnoreUnexported(jose.Header{})); len(d) > 0 {
		t.Errorf("header (-want, +got): %s", d)
	}

	got := jwt.Claims{}
	if err := tok.UnsafeClaimsWithoutVerification(&got); err != nil {
		t.Fatalf("UnsafeClaimsWithoutVerification() failed: %v", err)
	}

	if d := cmp.Diff(claims, got); len(d) > 0 {
		t.Errorf("claims in token (-want, +got): %s", d)
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

	listVerReq  *kmspb.ListCryptoKeyVersionsRequest
	listVerResp *kmspb.ListCryptoKeyVersionsResponse
	listVerErr  error

	getPubKeyReq  *kmspb.GetPublicKeyRequest
	getPubKeyResp *rpb.PublicKey
	getPubKeyErr  error

	signReq  *kmspb.AsymmetricSignRequest
	signResp *kmspb.AsymmetricSignResponse
	signErr  error
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
func (s *stubKMS) ListCryptoKeyVersions(ctx context.Context, req *kmspb.ListCryptoKeyVersionsRequest) (*kmspb.ListCryptoKeyVersionsResponse, error) {
	s.listVerReq = proto.Clone(req).(*kmspb.ListCryptoKeyVersionsRequest)
	return proto.Clone(s.listVerResp).(*kmspb.ListCryptoKeyVersionsResponse), s.listVerErr
}
func (s *stubKMS) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest) (*rpb.PublicKey, error) {
	s.getPubKeyReq = proto.Clone(req).(*kmspb.GetPublicKeyRequest)
	return proto.Clone(s.getPubKeyResp).(*rpb.PublicKey), s.getPubKeyErr
}
func (s *stubKMS) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest) (*kmspb.AsymmetricSignResponse, error) {
	s.signReq = proto.Clone(req).(*kmspb.AsymmetricSignRequest)
	return proto.Clone(s.signResp).(*kmspb.AsymmetricSignResponse), s.signErr
}
