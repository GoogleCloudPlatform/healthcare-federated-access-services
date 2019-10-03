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

package main

import (
	"fmt"
	"time"

	"github.com/pborman/uuid"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys"
)

// PassportBroker (B)
type PassportBroker struct {
	I   *VisaIssuer
	Key testkeys.Key
}

// FetchPassport fetches the requested Passport.
func (b *PassportBroker) FetchPassport(t Token) (ga4gh.PassportJWT, error) {
	// VerifyToken(t)
	// I := ExtractVisaIssuer(t)

	j, err := b.I.FetchVisa(t)
	if err != nil {
		return "", fmt.Errorf("FetchPassport(%v) failed:\n%v", t, err)
	}

	v, err := ga4gh.NewVisaFromJWT(j)
	if err != nil {
		return "", fmt.Errorf("NewVisaFromJWT(%v) failed:\n%v", j, err)
	}

	// Optional
	if err := v.Verify(b.I.Key.Public); err != nil {
		return "", fmt.Errorf("Visa(%v).Verify(%v) failed:\n%v", v, b.I.Key.Public, err)
	}

	d := &ga4gh.PassportData{
		StdClaims: ga4gh.StdClaims{
			Id:        uuid.New(),
			Issuer:    "B",
			Subject:   string(t),
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
			Audience:  "C",
		},
		Visas: []*ga4gh.Visa{v},
	}

	p, err := ga4gh.NewPassportFromData(d, ga4gh.RS256, b.Key.Private, "kid")
	if err != nil {
		return "", fmt.Errorf("NewPassportFromData(%v,%v,%v) failed:\n%v", d, ga4gh.RS256, b.Key.Private, err)
	}
	return p.JWT(), nil
}
