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
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/dgrijalva/jwt-go"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys"
)

func TestNewVisaFromData(t *testing.T) {
	d, j := fakeVisaDataAndJWT(t)

	v, err := NewVisaFromData(d, RS256, testkeys.PrivateKey)
	if err != nil {
		t.Fatalf("NewVisaFromData(%v) failed: %v", d, err)
	}
	got := v.JWT()

	want := j
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("NewVisaFromData(%v) returned diff (-want +got):\n%s", d, diff)
	}
}

func TestNewVisaFromJWT(t *testing.T) {
	d, j := fakeVisaDataAndJWT(t)

	v, err := NewVisaFromJWT(j)
	if err != nil {
		t.Fatalf("NewVisaFromJWT(%v) failed: %v", j, err)
	}
	got := v.Data()

	want := d
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("NewVisaFromJWT(%v) returned diff (-want +got):\n%s", j, diff)
	}
}

func TestVisaJSONFormat(t *testing.T) {
	_, j := fakeVisaDataAndJWT(t)
	got, err := payloadFromJWT(string(j))
	if err != nil {
		t.Fatalf("payloadFromJWT(%v) failed: %v", j, err)
	}
	want := fakeVisaDataJSON()
	if diff := cmp.Diff(jsontxt(want), jsontxt(got), cmp.Transformer("", jsontxtCanonical)); diff != "" {
		t.Fatalf("JSON(%v) returned diff (-want +got):\n%s", j, diff)
	}
}

func TestVisaVerify(t *testing.T) {
	d, _ := fakeVisaDataAndJWT(t)

	p, err := NewVisaFromData(d, RS256, testkeys.PrivateKey)
	if err != nil {
		t.Fatalf("NewPassportFromData(%v) failed: %v", d, err)
	}

	if err := p.Verify(testkeys.PublicKey); err != nil {
		t.Fatalf("Verify(_) failed: %v", err)
	}
}

func fakeVisaDataAndJWT(t *testing.T) (*VisaData, VisaJWT) {
	t.Helper()

	d := fakeVisaData()
	token := jwt.NewWithClaims(RS256, d)
	signed, err := token.SignedString(testkeys.PrivateKey)
	if err != nil {
		t.Fatalf("token.SignedString(_) failed: %v", err)
	}
	j := VisaJWT(signed)

	t.Logf("Data: %v", d)
	t.Logf("JWT: %v", j)
	t.Logf("You can verify the Data and JWT match on https://jwt.io/")

	return d, j
}

func fakeStart() int64 { return time.Date(2000, 8, 7, 6, 5, 4, 3, time.UTC).Unix() }

func fakeEnd() int64 { return time.Date(9999, 8, 7, 6, 5, 4, 3, time.UTC).Unix() }

func fakeVisaData() *VisaData {
	return &VisaData{
		JWT: JWT{
			Issuer:    "fake-visa-issuer",
			ExpiresAt: fakeEnd(),
		},
		Claim: Claim{
			Type:     "fake-visa-type",
			Value:    "fake-visa-value",
			Source:   "fake-visa-source",
			Asserted: fakeStart(),
			By:       "fake-visa-by",
			Conditions: [][]Condition{
				{
					{
						Type:   "AffiliationAndRole",
						Value:  "const:faculty@fake-institution.edu",
						Source: "",
						By:     "const:so",
					},
					{
						Type:   "AcceptedTermsAndPolicies",
						Value:  "",
						Source: "",
						By:     "",
					},
				},
				{
					{
						Type:   "AffiliationAndRole",
						Value:  "glob:faculty@*",
						Source: "const:https://fake-broker.org",
						By:     "const:system",
					},
					{
						Type:   "AcceptedTermsAndPolicies",
						Value:  "",
						Source: "",
						By:     "",
					},
				},
			},
		},
	}
}

func fakeVisaDataJSON() string {
	return `{
  "exp": ` + fmt.Sprintf("%v", fakeEnd()) + `,
  "iss": "fake-visa-issuer",
  "ga4gh_visa_v1": {
    "type": "fake-visa-type",
    "value": "fake-visa-value",
    "source": "fake-visa-source",
    "asserted": ` + fmt.Sprintf("%v", fakeStart()) + `,
    "by": "fake-visa-by",
    "conditions": [
      [
        {
          "type": "AffiliationAndRole",
          "value": "const:faculty@fake-institution.edu",
          "by": "const:so"
        },
        {
          "type": "AcceptedTermsAndPolicies"
        }
      ],
      [
        {
          "type": "AffiliationAndRole",
          "value": "glob:faculty@*",
          "source": "const:https://fake-broker.org",
          "by": "const:system"
        },
        {
          "type": "AcceptedTermsAndPolicies"
        }
      ]
    ]
  }
}`
}
