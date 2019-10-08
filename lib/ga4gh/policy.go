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
	"context"
	"fmt"

	glog "github.com/golang/glog"
)

// Issuer is a Visa Issuer.
type Issuer string

// TrustedIssuers contains the list of trusted Visa Issuers for each Source.
// Claims from issuers which are not trusted for the source must be ignored.
// If an issuer is trusted but no sources are listed then it is trusted for all.
type TrustedIssuers map[Issuer]map[Source]bool

// HasTrustedIssuer checks if a given Visa has a trusted issuer.
func HasTrustedIssuer(v *Visa, t TrustedIssuers) bool {
	glog.V(1).Info("HasTrustedIssuer")
	sources, ok := t[Issuer(v.Data().Issuer)]
	if !ok {
		return false
	}
	if sources == nil {
		return true
	}
	if sources[v.Data().Assertion.Source] {
		return true
	}
	return false
}

// TrustedSources contains the list of trusted Assertion Sources for each Assertion.
// Claims from sources which are not trusted for the Assertion must be ignored.
// E.g. Source "standford" can be trusted for "AffiliationAndRole" claims
// about "*@stanford.edu".
// If a source is trusted but no types are listed then it is trusted for all.
// If a source is trusted for a type but no RE are listed then it is ".*".
type TrustedSources map[Source]map[Type][]RegExp

// HasTrustedSource checks if a Visa has a trusted source.
func HasTrustedSource(v *Visa, t TrustedSources) bool {
	glog.V(1).Info("HasTrustedSource")
	a := v.Data().Assertion

	types, ok := t[a.Source]
	if !ok {
		return false
	}
	if types == nil {
		return true
	}

	res, ok := types[a.Type]
	if !ok {
		return false
	}
	if res == nil {
		return true
	}

	return matchRES(res, a.Value)
}

// matchRES checks if a value matches one of the given list of RE2s.
func matchRES(lst []RegExp, x Value) bool {
	glog.V(1).Info("matchRES")
	for _, e := range lst {
		if MatchRegExp(e, x) {
			return true
		}
	}
	return false
}

// Policy for a resource/view/role.
// Used in Passport Clearinghouse.
type Policy struct {
	issuers TrustedIssuers
	sources TrustedSources
	allow   Conditions
	deny    Conditions
	// verifier checks verifies the signature of the given token.
	verifier JWTVerifier
}

// JWTVerifier verifies the JWT token.
// It might make calls to external services, e.g. to obtain public key.
type JWTVerifier func(context.Context, string) error

// defailtVerifier is a no-op verifier.
func defaultVerifier(ctx context.Context, jwt string) error {
	glog.V(1).Info("defaultVerifier")
	return nil
}

// NewPolicy creates a new Policy.
// A passport would satisfy the policy if, after filtering and restricting
// Visas to those from TrustedIssuers and TrustedSource,
// allow is true and deny is false, and
// Condtions inside the Visas are true.
// If no deny is unspecified (nil), it is ignored.
func NewPolicy(i TrustedIssuers, s TrustedSources, allow Conditions, deny Conditions, f JWTVerifier) (*Policy, error) {
	glog.V(1).Info("NewPolicy")
	if f == nil {
		f = defaultVerifier
	}
	return &Policy{
		issuers:  i,
		sources:  s,
		allow:    allow,
		deny:     deny,
		verifier: f,
	}, nil
}

// Test checks if the provided passport satisfies the policy.
// Presumes that the signatures on the Passport and its Visas have already been verified.
func (p *Policy) Test(ctx context.Context, r *Passport) error {
	glog.V(1).Info("Policy.Test")

	// Filter assertions in the passport by issuer and source.
	vs := r.Visas
	glog.V(1).Infof("Number of Visas in the passport: %v", len(vs))

	vs = filterByIssuers(vs, p.issuers)
	glog.V(1).Infof("Number of Visas after filtering for trusted issuers: %v", len(vs))

	vs = filterBySources(vs, p.sources)
	glog.V(1).Infof("Number of Visas after filtering for trusted sources: %v", len(vs))

	// TODO: can we check only the ones used in allow and deny?
	if err := CheckLinkedIDs(vs); err != nil {
		return err
	}

	if p.deny != nil {
		if err := CheckConditions(ctx, p.deny, vs, p.verifier); err == nil {
			return fmt.Errorf("policy deny is satisfied")
		}
	}

	if err := CheckConditions(ctx, p.allow, vs, p.verifier); err != nil {
		return fmt.Errorf("policy allow is not satisfied")
	}

	// Check the conditions of the Visas that were used.
	// TODO: The specs only requires checking conditions on Visas that
	// are used. Can we do that? If we only check that visas without conditions
	// satisfy them then likely yes, we pass the visas without conditions down the
	// stack and check them when deciding to use a condition or not.
	for _, v := range vs {
		if err := CheckConditions(ctx, v.Data().Assertion.Conditions, vs, p.verifier); err != nil {
			return fmt.Errorf("Visa assertion conditions are not satisfied: %v", err)
		}
	}

	return nil
}

func filterByIssuers(vs []*Visa, t TrustedIssuers) []*Visa {
	glog.V(1).Info("filterByIssuers")
	var filtered []*Visa
	for _, v := range vs {
		if HasTrustedIssuer(v, t) {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

func filterBySources(vs []*Visa, t TrustedSources) []*Visa {
	glog.V(1).Info("filterBySources")
	var filtered []*Visa
	for _, v := range vs {
		if HasTrustedSource(v, t) {
			filtered = append(filtered, v)
		}
	}
	return filtered
}
