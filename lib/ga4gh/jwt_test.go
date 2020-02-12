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

package ga4gh

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */
)

const (
	fakeJWT     = `eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.JlX3gXGyClTBFciHhknWrjo7SKqyJ5iBO0n-3S2_I7cIgfaZAeRDJ3SQEbaPxVC7X8aqGCOM-pQOjZPKUJN8DMFrlHTOdqMs0TwQ2PRBmVAxXTSOZOoEhD4ZNCHohYoyfoDhJDP4Qye_FCqu6POJzg0Jcun4d3KW04QTiGxv2PkYqmB7nHxYuJdnqE3704hIS56pc_8q6AW0WIT0W-nIvwzaSbtBU9RgaC7ZpBD2LiNE265UBIFraMDF8IAFw9itZSUCTKg1Q-q27NwwBZNGYStMdIBDor2Bsq5ge51EkWajzZ7ALisVp-bskzUsqUf77ejqX_CBAqkNdH1Zebn93A`
	fakeJWTJSON = `{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true,
  "iat": 1516239022
}`
)

func TestJWTMultipleAudiences(t *testing.T) {
	// TODO
}

func TestStdClaims_Valid(t *testing.T) {
	c := &StdClaims{}
	if err := c.Valid(); err != nil {
		t.Fatalf("claims.Valid() failed: %v", err)
	}
}

func TestStdClaims_Valid_Invalid(t *testing.T) {
	c := &StdClaims{
		ExpiresAt: time.Now().Add(-time.Hour).Unix(),
	}
	if err := c.Valid(); err == nil {
		t.Fatal("claims.Valid() should fail when the claim is not valid.")
	}
}

func TestNewStdClaimsFromJWT(t *testing.T) {
	j := fakeJWT

	got, err := NewStdClaimsFromJWT(j)
	if err != nil {
		t.Fatalf("NewStdClaimsFromJWT() failed: %v", err)
	}

	want := &StdClaims{
		IssuedAt: 1516239022,
		Subject:  "1234567890",
	}

	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Fatalf("NewStdClaimsFromJWT returned diff (-want +got):\n%s", diff)
	}
}

func TestNewStdClaimsFromJWT_BadJWTFails(t *testing.T) {
	j := ``
	if _, err := NewStdClaimsFromJWT(j); err == nil {
		t.Fatal("NewStdClaimsFromJWT() should fail when JWT does not parse.")
	}
}

func Test_payloadFromJWT(t *testing.T) {
	j := fakeJWT
	got, err := payloadFromJWT(j)
	if err != nil {
		t.Fatalf("payloadFromJWT() failed: %v", err)
	}

	want := fakeJWTJSON
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("payloadFromJWT() returned diff (-want +got):\n%s", diff)
	}
}

func Test_payloadFromJWT_Fail(t *testing.T) {
	if _, err := payloadFromJWT(""); err == nil {
		t.Fatal("payloadFromJWT() should fail when input is invalid.")
	}
}

func Test_jsontxtCanonicalize(t *testing.T) {
	got, err := jsontxtCanonicalize(jsontxt(fakeJWTJSON))
	if err != nil {
		t.Fatalf("jsontxtCanonicalize() failed: %v", err)
	}

	want := `{
  "admin": true,
  "iat": 1516239022,
  "name": "John Doe",
  "sub": "1234567890"
}`
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("jsontxtCanonicalize() returned diff (-want +got):\n%s", diff)
	}
}

func Test_jsontxtCanonicalize_Fail(t *testing.T) {
	if _, err := jsontxtCanonicalize(""); err == nil {
		t.Fatal("jsontxtCanonicalize() should fail when input is invalid.")
	}
}
