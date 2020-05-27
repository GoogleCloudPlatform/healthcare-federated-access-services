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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */

	glog "github.com/golang/glog" /* copybara-comment */
)

const (
	fakeJWT1     = `eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.JlX3gXGyClTBFciHhknWrjo7SKqyJ5iBO0n-3S2_I7cIgfaZAeRDJ3SQEbaPxVC7X8aqGCOM-pQOjZPKUJN8DMFrlHTOdqMs0TwQ2PRBmVAxXTSOZOoEhD4ZNCHohYoyfoDhJDP4Qye_FCqu6POJzg0Jcun4d3KW04QTiGxv2PkYqmB7nHxYuJdnqE3704hIS56pc_8q6AW0WIT0W-nIvwzaSbtBU9RgaC7ZpBD2LiNE265UBIFraMDF8IAFw9itZSUCTKg1Q-q27NwwBZNGYStMdIBDor2Bsq5ge51EkWajzZ7ALisVp-bskzUsqUf77ejqX_CBAqkNdH1Zebn93A`
	fakeJWTJSON1 = `{
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true,
  "iat": 1516239022
}`
	fakeJWT2     = `eyJhbGciOiJSUzI1NiIsImtpZCI6Imh0dHA6Ly9bOjoxXTo0Njg2NS9pc3N1ZXIwIiwidHlwIjoiSldUIn0.eyJhdWQiOlsiZmFrZS1jbGllbnQiXSwiZXhwIjoxNTgxNzAzMjcwLCJpc3MiOiJodHRwOi8vWzo6MV06NDY4NjUvaXNzdWVyMCIsInN1YiI6ImZha2Utc3ViamVjdCIsImdhNGdoX3Zpc2FfdjEiOnt9fQ.NYpSCw4uvsca5014hvjEmRRB-d-v5JfUYHdRxUCnp-SSDAa2NVNptpkCdF0ExgFxRJcw3FRVkphc3dP9y0JHVeDbT4pfPs0lmPfK-OZ95Il24pF1XHQro8szNX2OybTMtbCGgtZ-6SRy7wObVXgfAnka1dOOugADx2myThttDHY`
	fakeJWTJSON2 = `{
  "aud": [
    "fake-client"
  ],
  "exp": 1581703270,
  "iss": "http://[::1]:46865/issuer0",
  "sub": "fake-subject",
  "ga4gh_visa_v1": {}
}`
)

func TestJWTMultipleAudiences(t *testing.T) {
	// TODO
}

func TestNewStdClaimsFromJWT(t *testing.T) {
	j := fakeJWT1

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

func TestNewStdClaimsFromJWT_AudienceList(t *testing.T) {
	j := fakeJWT2

	got, err := NewStdClaimsFromJWT(j)
	if err != nil {
		t.Fatalf("NewStdClaimsFromJWT() failed: %v", err)
	}

	want := &StdClaims{
		Audience:  NewAudience("fake-client"),
		ExpiresAt: 1581703270,
		Issuer:    "http://[::1]:46865/issuer0",
		Subject:   "fake-subject",
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
	j := fakeJWT1
	got, err := payloadFromJWT(j)
	if err != nil {
		t.Fatalf("payloadFromJWT() failed: %v", err)
	}

	want := fakeJWTJSON1
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
	got, err := jsontxtCanonicalize(jsontxt(fakeJWTJSON1))
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

var indent = "  "

// payloadFromJWT extracts and returns the decoded JSON of a JWT payload.
// Useful for logging and testing JSON format of payload.
// The JSON string uses "indent" for indention.
func payloadFromJWT(j string) (string, error) {
	parts := strings.Split(j, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid jwt format")
	}

	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	payload := &bytes.Buffer{}
	if err := json.Indent(payload, decoded, "", indent); err != nil {
		return "", err
	}

	return payload.String(), nil
}

// jsontxt is used internally for transforming for cmp.Diff.
// Allowing getting stable diff in comparing JSON text strings.
// Example:
// diff := cmp.Diff(jsontxt(want), jsontxt(got), cmp.Transformer("", jsontxtCanonical))
type jsontxt string

func jsontxtCanonical(j jsontxt) string {
	s, err := jsontxtCanonicalize(j)
	if err != nil {
		glog.Fatalf("jsontxtCanonicalize() failed: %v", err)
	}
	return s
}

func jsontxtCanonicalize(j jsontxt) (string, error) {
	var s interface{}
	if err := json.Unmarshal([]byte(j), &s); err != nil {
		return "", fmt.Errorf("json.Unmarshal(%v) failed: %v", j, err)
	}
	d, err := json.Marshal(&s)
	if err != nil {
		return "", fmt.Errorf("json.Marshal(%v) failed: %v", s, err)
	}
	c := &bytes.Buffer{}
	if err := json.Indent(c, d, "", indent); err != nil {
		return "", fmt.Errorf("json.Indent(%v,%v,%v,%v) failed: %v", c, d, "", indent, err)
	}
	return c.String(), nil
}
