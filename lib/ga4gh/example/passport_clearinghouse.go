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

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
)

// Resource is a cloud resource.
type Resource string

// PassportClearinghouse (C)
type PassportClearinghouse struct {
	B *PassportBroker
}

// RequestAccess checks if the bearer has accesses to the requested resouce, if
// so grants access to it.
func (c *PassportClearinghouse) RequestAccess(r Resource, t Token) (Token, error) {
	// VerifyToken(t)
	// B := ExtractPassportBroker(t)

	j, err := c.B.FetchAccess(t)
	if err != nil {
		return "", fmt.Errorf("FetchAccess(%v) failed:\n%v", t, err)
	}

	a, err := ga4gh.NewAccessFromJWT(j)
	if err != nil {
		return "", fmt.Errorf("NewAccessFromJWT(%v) failed:\n%v", j, err)
	}

	if err := a.Verify(c.B.Key.Public); err != nil {
		return "", fmt.Errorf("Access(%v).Verify(%v) failed:\n%v", a, c.B.Key.Public, err)
	}

	p := ga4gh.Passport{Access: a}

	js, err := c.B.FetchVisas(t)
	if err != nil {
		return "", fmt.Errorf("FetchVisas(%v) failed:\n%v", j, err)
	}

	for _, j := range js {
		v, err := ga4gh.NewVisaFromJWT(j)
		if err != nil {
			return "", fmt.Errorf("NewVisaFromJWT(%v) failed:\n%v", j, err)
		}
		if err := v.Verify(c.B.I.Key.Public); err != nil {
			return "", fmt.Errorf("Visa(%v).Verify(%v) failed:\n%v", v, c.B.I.Key.Public, err)
		}
		p.Visas = append(p.Visas, v)
	}

	// Evaluate the Claims agains the Policy.

	// GrantAccess to r.

	return "access token", nil
}
