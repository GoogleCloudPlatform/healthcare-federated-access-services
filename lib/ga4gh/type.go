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
// Is a string that can contain wildchars ? and *.
// ? is interpreted as any single character, * is interpretted as any string.
// http://bit.ly/ga4gh-passport-v1#pattern-matching
type Pattern string

// Scope is the AAI Scope claim
// http://bit.ly/ga4gh-aai-profile#ga4gh-jwt-format
type Scope string
