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
	"regexp"
	"strings"
)

// Timestamp is the number of seconds since epoch.
type Timestamp = int64

// Type is known GA4GH Assertion types.
// http://bit.ly/ga4gh-passport-v1#type
type Type string

const (
	// AffiliationAndRole Assertion type.
	// http://bit.ly/ga4gh-passport-v1#affiliationandrole
	AffiliationAndRole Type = "AffiliationAndRole"

	// AcceptedTermsAndPolicies Assertion type.
	// http://bit.ly/ga4gh-passport-v1#acceptedtermsandpolicies
	AcceptedTermsAndPolicies Type = "AcceptedTermsAndPolicies"

	// ResearcherStatus Assertion type.
	// http://bit.ly/ga4gh-passport-v1#researcherstatus
	ResearcherStatus Type = "ResearcherStatus"

	// ControlledAccessGrants Assertion type.
	// http://bit.ly/ga4gh-passport-v1#controlledaccessgrants
	ControlledAccessGrants Type = "ControlledAccessGrants"

	// LinkedIdentities Assertion type.
	// http://bit.ly/ga4gh-passport-v1#linkedidentities
	LinkedIdentities Type = "LinkedIdentities"
)

// ValidType checks the Type of an Assertion is valid.
func ValidType(t Type) bool {
	return StandardType(t) || CustomType(t)
}

// StandardType checks if the Type of an Assertion is one of the standard ones.
// http://bit.ly/ga4gh-passport-v1#ga4gh-standard-passport-visa-type-definitions
func StandardType(t Type) bool {
	switch t {
	case AffiliationAndRole, AcceptedTermsAndPolicies, ResearcherStatus, ControlledAccessGrants, LinkedIdentities:
		return true
	}
	return false
}

// CustomType checks if the Type of an Assertion is a custom.
// http://bit.ly/ga4gh-passport-v1#custom-passport-visa-types
func CustomType(t Type) bool {
	// TODO: check that it is a valid URL.
	return true
}

// Value is the value of an Assertion.
// http://bit.ly/ga4gh-passport-v1#value
type Value string

// By is the By of an Assertion.
// http://bit.ly/ga4gh-passport-v1#by
type By string

const (
	// Self is the Pasport Visa Identity for which the assertion is being made and the person who made the assertion is the same person.
	Self By = "self"

	// Peer is a person at the source organization has made this assertion on behalf of the Passport Visa Identity's person, and the person who is making the assertion has the same Passport Visa Type and value in that source organization. The source field represents the peer’s organization that is making the assertion, which is not necessarily the same organization as the Passport Visa Identity's organization.
	Peer By = "peer"

	// System is the source organization’s information system has made the assertion based on system data or metadata that it stores.
	System By = "system"

	// SO is a person (also known as "signing official") making the assertion within the source organization possesses direct authority (as part of their formal duties) to bind the organization to their assertion that the Passport Visa Identity, did possess such authority at the time the assertion was made.
	SO By = "so"

	// DAC is a Data Access Committee or other authority that is responsible as a grantee decision-maker for the given value and source field pair.)
	DAC By = "dac"
)

// Source is the Source of an Assertion.
// http://bit.ly/ga4gh-passport-v1#source
type Source string

// Pattern for a string from Pattern Matching section of GA4GH Passport sepcification.
// Pattern should be of one of the following forms:
// prefix = "const:": the field should be equal to the suffix
// prefix = "pattern:": the field should match the suffix
// prefix = "split_pattern": the field should match one of the parts of suffix after splitting by ;
// The only wildchars for matching are ? and *.
// ? is interpreted as any single character, * is interpretted as any string.
// http://bit.ly/ga4gh-passport-v1#pattern-matching
type Pattern string

// MatchPatterns checks if a given string matches a Pattern.
func MatchPatterns(p Pattern, v string) error {
	switch {
	case p == "": // No pattern is specified.
		return nil

	case strings.HasPrefix(string(p), "const:"):
		w := string(p[len("const:"):])
		if w != v {
			return fmt.Errorf("const not matched: %q %q", p, v)
		}
		return nil

	case strings.HasPrefix(string(p), "pattern:"):
		w := string(p[len("pattern:"):])
		if matchSuffix(w, v) != nil {
			return fmt.Errorf("pattern not matched: %q %q", p, v)
		}
		return nil

	case strings.HasPrefix(string(p), "split_pattern:"):
		ws := strings.Split(string(p[len("split_pattern:"):]), ";")
		for _, w := range ws {
			if matchSuffix(w, v) == nil {
				return nil
			}
		}
		return fmt.Errorf("split_pattern not matched: %q %q", p, v)

	}
	return fmt.Errorf("unkown pattern")
}

// matchSuffix gets a suffix for a pattern and checks if v matches it.
func matchSuffix(w string, v string) error {
	all := regexp.QuoteMeta("*")
	any := regexp.QuoteMeta("?")

	q := regexp.QuoteMeta(w)
	q = strings.ReplaceAll(q, all, "*")
	q = strings.ReplaceAll(q, any, ".")
	q = "^" + q + "$"

	// TODO: use global regexp cache.
	r, err := regexp.Compile(q)
	if err != nil {
		return fmt.Errorf("invalid pattern matching strings: %q", w)
	}

	if !r.MatchString(v) {
		return fmt.Errorf("pattern not matched:%q %q", w, v)
	}

	return nil
}

// RegExp is a RE2 string.
// https://golang.org/s/re2syntax
type RegExp string

// MatchRegExp checks if a value matches one of the given list of RE2s.
func MatchRegExp(e RegExp, x Value) bool {
	// TODO: add a (global) cache for r.
	r, err := regexp.Compile(string(e))
	if err != nil {
		return false
	}
	if r.MatchString(string(x)) {
		return true
	}
	return false
}

// Scope is the AAI Scope claim
// http://bit.ly/ga4gh-aai-profile#ga4gh-jwt-format
type Scope string

// TODO: add tests for this file.
