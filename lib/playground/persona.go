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

package playground

import (
	"fmt"
	"strings"
	"time"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh"

	dampb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1"
)

var (
	// StandardClaims is the list of standard OIDC claims that personas import into GA4GH Identity objects.
	StandardClaims = map[string]string{
		"azp":                "Authorized Party (application identifier)",
		"email":              "Email address",
		"email_verified":     "Email Verified (true or false)",
		"family_name":        "Family Name",
		"given_name":         "Given Name",
		"iss":                "Issuer of the Passport",
		"locale":             "Locale",
		"middle_name":        "Middle Name",
		"name":               "Full Name",
		"nickname":           "Nickname",
		"picture":            "Picture",
		"preferred_username": "Preferred Username",
		"profile":            "Profile",
		"sub":                "Subject (user identifier)",
		"zoneinfo":           "Zone info (timezone)",
	}
	// minPersonaFutureExpiry prevents users from setting expiries too close to now() that execution
	// time across many personas may cause a test to accidently fail.
	minPersonaFutureExpiry = 5 * time.Second
)

func PersonaToIdentity(name string, persona *dampb.TestPersona, scope string) (*ga4gh.Identity, error) {
	if persona.IdToken == nil {
		return nil, fmt.Errorf("persona %q has not configured a test identity token", name)
	}
	sub := getStandardClaim(persona, "sub")
	if len(sub) == 0 {
		sub = name
	}
	firstName := getStandardClaim(persona, "firstName")
	lastName := getStandardClaim(persona, "lastName")
	fullName := getStandardClaim(persona, "name")
	if len(fullName) == 0 && persona.Ui != nil && len(persona.Ui["label"]) > 0 {
		fullName = persona.Ui["label"]
	}
	splitName := strings.Split(fullName, " ")
	if len(splitName) > 0 && len(firstName) == 0 {
		firstName = splitName[0]
	}
	if len(splitName) > 1 && len(lastName) == 0 {
		lastName = splitName[1]
	}
	if len(splitName) == 1 && len(lastName) > 0 {
		fullName = fullName + " " + lastName
	} else if len(splitName) == 0 && len(firstName) > 0 && len(lastName) > 0 {
		fullName = firstName + " " + lastName
	} else if len(splitName) == 0 && len(firstName) > 0 {
		fullName = firstName + " Persona"
	} else if len(splitName) == 0 && len(lastName) > 0 {
		fullName = "Sam " + lastName
	} else if len(splitName) == 0 {
		names := strings.FieldsFunc(name, nameSplit)
		if len(names) > 1 {
			fullName = strings.Join(names, " ")
		} else {
			fullName = name + " Persona"
		}
		if len(firstName) == 0 {
			firstName = names[0]
		}
		if len(lastName) == 0 {
			if len(names) > 1 {
				lastName = names[1]
			} else {
				lastName = "Persona"
			}
		}
	}
	if len(firstName) == 0 || len(lastName) == 0 {
		splitName = strings.Split(fullName, " ")
		if len(firstName) == 0 {
			firstName = splitName[0]
		}
		if len(lastName) == 0 {
			if len(splitName) > 1 {
				lastName = splitName[1]
			} else {
				lastName = "Persona"
			}
		}
	}
	nickname := getStandardClaim(persona, "nickname")
	if nickname == "" {
		nickname = strings.Split(toName(name), " ")[0]
	}

	identity := ga4gh.Identity{
		Subject:         sub,
		Email:           getStandardClaim(persona, "email"),
		Issuer:          getStandardClaim(persona, "iss"),
		Expiry:          time.Now().Add(180 * 24 * time.Hour).Unix(),
		Scope:           scope,
		AuthorizedParty: getStandardClaim(persona, "azp"),
		Username:        name,
		EmailVerified:   getStandardClaim(persona, "email_verified") != "false",
		Name:            toName(fullName),
		Nickname:        nickname,
		GivenName:       toName(firstName),
		FamilyName:      toName(lastName),
		MiddleName:      getStandardClaim(persona, "middle_name"),
		ZoneInfo:        getStandardClaim(persona, "zoneinfo"),
		Locale:          getStandardClaim(persona, "locale"),
		Picture:         getStandardClaim(persona, "picture"),
		Profile:         getStandardClaim(persona, "profile"),
	}
	if persona.IdToken.Ga4GhClaims == nil || len(persona.IdToken.Ga4GhClaims) == 0 {
		return &identity, nil
	}
	return populatePersonaClaims(name, persona.IdToken.Ga4GhClaims, &identity)
}

func toName(input string) string {
	return strings.Join(strings.FieldsFunc(input, nameSplit), " ")
}

func nameSplit(r rune) bool {
	return r == ' ' || r == '_' || r == '.' || r == '-'
}

func getStandardClaim(persona *dampb.TestPersona, claim string) string {
	if persona.IdToken.StandardClaims == nil || len(persona.IdToken.StandardClaims[claim]) == 0 {
		return ""
	}
	return persona.IdToken.StandardClaims[claim]
}

func populatePersonaClaims(pname string, claims []*dampb.TestPersona_GA4GHClaim, id *ga4gh.Identity) (*ga4gh.Identity, error) {
	issuer := id.Issuer
	id.GA4GH = make(map[string][]ga4gh.Claim)
	now := float64(time.Now().Unix())

	for i, claim := range claims {
		cname := claim.ClaimName
		if len(cname) == 0 {
			return nil, fmt.Errorf("persona %q claim %d missing claim name", pname, i+1)
		}
		if len(claim.Value) == 0 {
			return nil, fmt.Errorf("persona %q claim %d missing claim value", pname, i+1)
		}
		src := issuer
		if len(claim.Source) > 0 {
			src = claim.Source
		}
		_, ok := id.GA4GH[cname]
		if !ok {
			id.GA4GH[cname] = make([]ga4gh.Claim, 0)
		}
		// claim.AssertedDuration cannot be negative and is assumed to be a duration in the past.
		a, err := common.ParseDuration(claim.AssertedDuration, 120*time.Second)
		if err != nil {
			return nil, fmt.Errorf("persona %q claim %d asserted duration %q: %v", pname, i+1, claim.AssertedDuration, err)
		}
		asserted := now - a.Seconds()
		// claim.ExpiresDuration may be negative or positive where a negative value represents the past.
		e, err := common.ParseNegDuration(claim.ExpiresDuration, 30*24*time.Hour)
		if err != nil {
			return nil, fmt.Errorf("persona %q claim %d expires duration %q: %v", pname, i+1, claim.ExpiresDuration, err)
		}
		if e > 0 && e < minPersonaFutureExpiry {
			e = minPersonaFutureExpiry
		}
		expires := now + e.Seconds()
		c := ga4gh.Claim{
			Value:    claim.Value,
			Source:   src,
			Asserted: asserted,
			Expires:  expires,
			By:       claim.By,
		}
		if claim.Condition != nil {
			c.Condition = make(map[string]ga4gh.ClaimCondition)
			for k, v := range claim.Condition {
				c.Condition[k] = ga4gh.ClaimCondition{
					Value:  v.Value,
					Source: v.Source,
					By:     v.By,
				}
			}
		}

		id.GA4GH[cname] = append(id.GA4GH[cname], c)
	}
	return id, nil
}
