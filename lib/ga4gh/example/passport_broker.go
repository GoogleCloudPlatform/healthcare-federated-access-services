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
	"context"
	"fmt"
	"time"

	"github.com/pborman/uuid" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/kms/localsign" /* copybara-comment: localsign */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */
)

// PassportBroker (B)
type PassportBroker struct {
	I   *VisaIssuer
	Key testkeys.Key
}

// FetchAccess fetches the requested Access.
func (b *PassportBroker) FetchAccess(t Token) (ga4gh.AccessJWT, error) {
	// VerifyToken(t)
	// I := ExtractVisaIssuer(t)

	d := &ga4gh.AccessData{
		StdClaims: ga4gh.StdClaims{
			ID:        uuid.New(),
			Issuer:    "B",
			Subject:   string(t),
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
			Audience:  ga4gh.NewAudience("C"),
		},
	}

	ctx := context.Background()
	signer := localsign.New(&b.Key)
	p, err := ga4gh.NewAccessFromData(ctx, d, signer)
	if err != nil {
		return "", fmt.Errorf("NewAccessFromData() failed:\n%v", err)
	}
	return p.JWT(), nil
}

// FetchVisas fetches the request Visas.
func (b *PassportBroker) FetchVisas(t Token) ([]ga4gh.VisaJWT, error) {
	// VerifyToken(t)
	// I := ExtractVisaIssuer(t)

	j, err := b.I.FetchVisa(t)
	if err != nil {
		return nil, fmt.Errorf("FetchVisa(%v) failed:\n%v", t, err)
	}

	v, err := ga4gh.NewVisaFromJWT(j)
	if err != nil {
		return nil, fmt.Errorf("NewVisaFromJWT(%v) failed:\n%v", j, err)
	}

	return []ga4gh.VisaJWT{v.JWT()}, nil
}
