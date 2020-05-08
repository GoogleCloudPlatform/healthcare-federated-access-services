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

package persona

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/timeutil" /* copybara-comment: timeutil */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
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

	// DefaultScope is a list of standard scopes to request.
	DefaultScope = "openid ga4gh ga4gh_passport_v1"

	// AccountScope has default scopes and the account_admin scope.
	AccountScope = DefaultScope + " account_admin"

	// LinkScope has account scope plus the additional account-linking scope.
	LinkScope = AccountScope + " link"

	// minPersonaFutureExpiry prevents users from setting expiries too close to now() that execution
	// time across many personas may cause a test to accidently fail.
	minPersonaFutureExpiry = 5 * time.Second

	personaKey = testkeys.Keys[testkeys.PersonaBroker]
)

// NewAccessToken returns an access token for a persona at a given issuer.
// The persona parameter may be nil.
func NewAccessToken(name, issuer, clientID, scope string, persona *cpb.TestPersona) (ga4gh.AccessJWT, string, error) {
	now := time.Now().Unix()
	sub := name
	email := name
	if persona != nil {
		if s := getStandardClaim(persona, "sub"); len(s) > 0 {
			sub = s
			email = s
		}
		if e := getStandardClaim(persona, "email"); len(e) > 0 {
			email = e
		}
	}
	if len(scope) == 0 {
		scope = DefaultScope
	}
	d := &ga4gh.AccessData{
		StdClaims: ga4gh.StdClaims{
			Issuer:    issuer,
			Subject:   sub,
			IssuedAt:  now,
			ExpiresAt: now + 10000,
			Audience:  ga4gh.NewAudience(clientID),
			ID:        "token-id-" + name,
		},
		Scope: scope,
		Identities: map[string][]string{
			email: []string{"IC", "DAM"},
		},
	}
	access, err := ga4gh.NewAccessFromData(d, ga4gh.RS256, personaKey.Private, personaKey.ID)
	if err != nil {
		return "", "", err
	}
	return access.JWT(), sub, nil
}

// ToIdentity retuns an Identity from persona configuration settings.
func ToIdentity(name string, persona *cpb.TestPersona, scope, visaIssuer string) (*ga4gh.Identity, error) {
	if persona.Passport == nil {
		return nil, fmt.Errorf("persona %q has not configured a test identity token", name)
	}
	sub := getStandardClaim(persona, "sub")
	if len(sub) == 0 {
		sub = name
	}

	iss := visaIssuer
	if len(iss) == 0 {
		iss = getStandardClaim(persona, "iss")
		visaIssuer = iss
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

	email := getStandardClaim(persona, "email")
	identity := ga4gh.Identity{
		Subject:         sub,
		Email:           email,
		Issuer:          iss,
		Expiry:          time.Now().Add(180 * 24 * time.Hour).Unix(),
		Scope:           scope,
		AuthorizedParty: getStandardClaim(persona, "azp"),
		Username:        name,
		EmailVerified:   strings.ToLower(getStandardClaim(persona, "email_verified")) == "true",
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

	if email != "" {
		if persona.Passport.Ga4GhAssertions == nil {
			persona.Passport.Ga4GhAssertions = []*cpb.Assertion{}
		}
		assert := &cpb.Assertion{
			Type:             "LinkedIdentities",
			Value:            url.QueryEscape(email) + "," + url.QueryEscape(visaIssuer),
			Source:           visaIssuer,
			By:               "system",
			AssertedDuration: "30d",
			ExpiresDuration:  "30d",
		}
		persona.Passport.Ga4GhAssertions = append(persona.Passport.Ga4GhAssertions, assert)
	}
	if persona.Passport.Ga4GhAssertions == nil || len(persona.Passport.Ga4GhAssertions) == 0 {
		return &identity, nil
	}
	return populatePersonaVisas(name, visaIssuer, persona.Passport.Ga4GhAssertions, &identity)
}

func toName(input string) string {
	return strings.Join(strings.FieldsFunc(input, nameSplit), " ")
}

func nameSplit(r rune) bool {
	return r == ' ' || r == '_' || r == '.' || r == '-'
}

func getStandardClaim(persona *cpb.TestPersona, claim string) string {
	if persona.Passport.StandardClaims == nil || len(persona.Passport.StandardClaims[claim]) == 0 {
		return ""
	}
	return persona.Passport.StandardClaims[claim]
}

func jkuURL(issuer string) string {
	return strings.TrimSuffix(issuer, "/") + "/.well-known/jwks"
}

func populatePersonaVisas(pname, visaIssuer string, assertions []*cpb.Assertion, id *ga4gh.Identity) (*ga4gh.Identity, error) {
	issuer := id.Issuer
	jku := jkuURL(issuer)
	id.GA4GH = make(map[string][]ga4gh.OldClaim)
	id.VisaJWTs = make([]string, len(assertions))
	now := float64(time.Now().Unix())

	for i, assert := range assertions {
		typ := ga4gh.Type(assert.Type)
		if len(typ) == 0 {
			return nil, fmt.Errorf("persona %q visa %d missing assertion type", pname, i+1)
		}
		_, ok := id.GA4GH[assert.Type]
		if !ok {
			id.GA4GH[assert.Type] = make([]ga4gh.OldClaim, 0)
		}
		if len(assert.Value) == 0 {
			return nil, fmt.Errorf("persona %q visa %d missing assertion value", pname, i+1)
		}
		src := ga4gh.Source(issuer)
		if len(assert.Source) > 0 {
			src = ga4gh.Source(assert.Source)
		}
		// assert.AssertedDuration cannot be negative and is assumed to be a duration in the past.
		a, err := timeutil.ParseDuration(assert.AssertedDuration)
		if err != nil {
			return nil, fmt.Errorf("persona %q visa %d asserted duration %q: %v", pname, i+1, assert.AssertedDuration, err)
		}
		asserted := int64(now - a.Seconds())
		// assert.ExpiresDuration may be negative or positive where a negative value represents the past.
		e, err := timeutil.ParseDuration(assert.ExpiresDuration)
		if err != nil {
			return nil, fmt.Errorf("persona %q visa %d expires duration %q: %v", pname, i+1, assert.ExpiresDuration, err)
		}
		if e > 0 && e < minPersonaFutureExpiry {
			e = minPersonaFutureExpiry
		}
		expires := int64(now + e.Seconds())
		visa := ga4gh.VisaData{
			StdClaims: ga4gh.StdClaims{
				Subject:   id.Subject,
				Issuer:    visaIssuer,
				ExpiresAt: expires,
				IssuedAt:  int64(now),
			},
			Assertion: ga4gh.Assertion{
				Type:     typ,
				Value:    ga4gh.Value(assert.Value),
				Source:   src,
				Asserted: asserted,
				By:       ga4gh.By(assert.By),
			},
		}
		if len(assert.AnyOfConditions) > 0 {
			visa.Assertion.Conditions = make(ga4gh.Conditions, 0)
			for _, cond := range assert.AnyOfConditions {
				clauses := []ga4gh.Condition{}
				for _, clause := range cond.AllOf {
					c := ga4gh.Condition{
						Type:   ga4gh.Type(clause.Type),
						Value:  ga4gh.Pattern(clause.Value),
						Source: ga4gh.Pattern(clause.Source),
						By:     ga4gh.Pattern(clause.By),
					}
					clauses = append(clauses, c)
				}
				visa.Assertion.Conditions = append(visa.Assertion.Conditions, clauses)
			}
		}

		v, err := ga4gh.NewVisaFromData(&visa, jku, ga4gh.RS256, personaKey.Private, personaKey.ID)
		if err != nil {
			return nil, fmt.Errorf("signing persona %q visa %d failed: %s", pname, i+1, err)
		}
		id.VisaJWTs[i] = string(v.JWT())

		// Populate old claims.
		c := ga4gh.OldClaim{
			Value:    assert.Value,
			Source:   string(src),
			Asserted: float64(asserted),
			Expires:  float64(expires),
			By:       assert.By,
		}
		if len(assert.AnyOfConditions) > 0 {
			c.Condition = make(map[string]ga4gh.OldClaimCondition)
			cType := ""
			cValue := []string{}
			cSource := []string{}
			cBy := []string{}
			for _, cond := range assert.AnyOfConditions {
				for _, clause := range cond.AllOf {
					cType = clause.Type
					clValue := clause.Value
					if clValues := strings.SplitN(clause.Value, ":", 2); len(clValues) > 1 {
						clValue = clValues[1]
					}
					clSource := clause.Source
					if clSources := strings.SplitN(clause.Source, ":", 2); len(clSources) > 1 {
						clSource = clSources[1]
					}
					clBy := clause.By
					if clBys := strings.SplitN(clause.By, ":", 2); len(clBys) > 1 {
						clBy = clBys[1]
					}
					if len(clValue) > 0 {
						cValue = append(cValue, clValue)
					}
					if len(clSource) > 0 {
						cSource = append(cSource, clSource)
					}
					if len(clBy) > 0 {
						cBy = append(cBy, clBy)
					}
				}
			}
			oldC := ga4gh.OldClaimCondition{}
			if len(cValue) > 0 {
				oldC.Value = cValue
			}
			if len(cSource) > 0 {
				oldC.Source = cSource
			}
			if len(cBy) > 0 {
				oldC.By = cBy
			}
			c.Condition[cType] = oldC
		}
		id.GA4GH[assert.Type] = append(id.GA4GH[assert.Type], c)
	}
	return id, nil
}
