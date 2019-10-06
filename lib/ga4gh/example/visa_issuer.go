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

// VisaIssuer (I)
type VisaIssuer struct {
	R   *ClaimRepository
	Key testkeys.Key
}

// FetchVisa fetches the requested Visa.
func (i *VisaIssuer) FetchVisa(t Token) (ga4gh.VisaJWT, error) {
	// VerifyToken(t)
	// I := ExtractClaimRepository(t)

	c, err := i.R.FetchClaim(t)
	if err != nil {
		return "", fmt.Errorf("FetchClaim(%v) failed:\n%v", t, err)
	}

	d := &ga4gh.VisaData{
		StdClaims: ga4gh.StdClaims{
			ID:        uuid.New(),
			Issuer:    "I",
			Subject:   string(t),
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
			Audience:  ga4gh.NewAudience("B"),
		},
		Assertion: c,
	}

	v, err := ga4gh.NewVisaFromData(d, ga4gh.RS256, i.Key.Private, "kid")
	if err != nil {
		return "", fmt.Errorf("NewVisaFromData(%v,%v,%v) failed:\n%v", d, ga4gh.RS256, i.Key.Private, err)
	}

	return v.JWT(), nil
}
