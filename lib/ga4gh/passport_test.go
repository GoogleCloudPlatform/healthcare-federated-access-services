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
	"fmt"
	"testing"

	glog "github.com/golang/glog"
	"github.com/google/go-cmp/cmp"
	"github.com/dgrijalva/jwt-go"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys"
)

const (
	fixedKeyID = "k"
)

func TestNewPassportFromData(t *testing.T) {
	d, j := fakePassportDataAndJWT(t)

	p, err := NewPassportFromData(d, RS256, testkeys.PrivateKey, fixedKeyID)
	if err != nil {
		t.Fatalf("NewPassportFromData(%v) failed: %v", err)
	}
	got := p.JWT()

	want := j
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("NewPassportFromData(%v) returned diff (-want +got):\n%s", d, diff)
	}
}

func TestNewPassportFromJWT(t *testing.T) {
	d, j := fakePassportDataAndJWT(t)

	p, err := NewPassportFromJWT(j)
	if err != nil {
		t.Fatalf("NewVisaFromJWT(%v) failed: %v", j, err)
	}
	got := p.Data()

	want := d
	if diff := cmp.Diff(want, got, cmp.AllowUnexported(Visa{})); diff != "" {
		t.Fatalf("NewVisaFromJWT(%v) returned diff (-want +got):\n%s", j, diff)
	}
}

func TestPassportJSONFormat(t *testing.T) {
	_, j := fakePassportDataAndJWT(t)
	got, err := payloadFromJWT(string(j))
	if err != nil {
		t.Fatalf("payloadFromJWT(%v) failed: %v", j, err)
	}
	want := fakePassportDataJSON()
	if diff := cmp.Diff(jsontxt(want), jsontxt(got), cmp.Transformer("", jsontxtCanonical)); diff != "" {
		t.Fatalf("JSON(%v) returned diff (-want +got):\n%s", j, diff)
	}
}

func TestPassportVerify(t *testing.T) {
	d, _ := fakePassportDataAndJWT(t)

	p, err := NewPassportFromData(d, RS256, testkeys.PrivateKey, fixedKeyID)
	if err != nil {
		t.Fatalf("NewPassportFromData(%v) failed: %v", d, err)
	}

	if err := p.Verify(testkeys.PublicKey); err != nil {
		t.Fatalf("Verify(_) failed: %v", err)
	}
}

func fakePassportDataAndJWT(t *testing.T) (*PassportData, PassportJWT) {
	t.Helper()

	d := fakePassportData()
	m := toPassportDataWithVisaJWT(d)
	token := jwt.NewWithClaims(RS256, m)
	token.Header[jwtHeaderKeyID] = fixedKeyID
	signed, err := token.SignedString(testkeys.PrivateKey)
	if err != nil {
		t.Fatalf("token.SignedString(_) failed: %v", err)
	}
	j := PassportJWT(signed)

	t.Logf("Data: %v", d)
	t.Logf("JWT: %v", j)
	t.Logf("You can verify the Data and JWT match on https://jwt.io/")

	return d, j
}

func fakeVisa() *Visa {
	v, err := NewVisaFromData(fakeVisaData(), RS256, testkeys.PrivateKey, fixedKeyID)
	if err != nil {
		glog.Fatalf("NewVisaFromData(fakeVisaData,_,_) failed: %v", err)
	}
	return v
}

func fakePassportData() *PassportData {
	return &PassportData{
		JWT: JWT{
			Id:        "fake-passport-id",
			Subject:   "fake-passport-subject",
			Issuer:    "fake-passport-issuer",
			IssuedAt:  fakeStart(),
			ExpiresAt: fakeEnd(),
		},
		Scope: "openid fake-passport-scope",
		Visas: []*Visa{fakeVisa()},
	}
}

func fakePassportDataJSON() string {
	return `{
    "exp": ` + fmt.Sprintf("%v", fakeEnd()) + `,
    "jti": "fake-passport-id",
    "iat": ` + fmt.Sprintf("%v", fakeStart()) + `,
    "iss": "fake-passport-issuer",
    "sub": "fake-passport-subject",
    "scope": "openid fake-passport-scope",
    "ga4gh_passport_v1": [
    "` + string(fakeVisa().JWT()) + `"
    ]
  }`
}
