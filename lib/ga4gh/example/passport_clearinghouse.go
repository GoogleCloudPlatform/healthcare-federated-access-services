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

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh"
)

// Resource is a cloud resource.
type Resource string

// PassportClearinghouse (C)
type PassportClearinghouse struct {
	B      *PassportBroker
	Policy ga4gh.Claim
}

// RequestAccess checks if the bearer has accesses to the requested resouce, if
// so grants access to it.
func (c *PassportClearinghouse) RequestAccess(r Resource, t Token) (Token, error) {
	// VerifyToken(t)
	// B := ExtractPassportBroker(t)

	j, err := c.B.FetchPassport(t)
	if err != nil {
		return "", fmt.Errorf("FetchPassport(%v) failed:\n%v", t, err)
	}

	p, err := ga4gh.NewPassportFromJWT(j)
	if err != nil {
		return "", fmt.Errorf("NewPassportFromJWT(%v) failed:\n%v", j, err)
	}

	if err := p.Verify(c.B.Key.Public); err != nil {
		return "", fmt.Errorf("Passport(%v).Verify(%v) failed:\n%v", p, c.B.Key.Public, err)
	}

	for _, v := range p.Data().Visas {
		if err := v.Verify(c.B.I.Key.Public); err != nil {
			return "", fmt.Errorf("Visa(%v).Verify(%v) failed:\n%v", v, c.B.I.Key.Public, err)
		}
	}

	// Evaluate the Claims agains the Policy.

	// GrantAccess to r.

	return "access token", nil
}
