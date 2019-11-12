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
	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1"
)

// Conditions represent a GA4GH Passport Visa condition field sub-object.
// https://docs.google.com/document/d/1NySsYM1V9ssxk_k4RH37fU4tJK8x37YMmDxnn_45FvQ/
type Conditions [][]Condition

// CheckConditions checks if the given list of Assertions satisfies the
// given Conditions.
// Conditions is a DNF, an OR of Clauses, each Clause an AND of Literals,
// each Literal a Condition.
// A list of Assertions satisfies a Condition if at least one of Assertions
// makes the Condition true.
// Visas which cannot be verified will be ignored.
func CheckConditions(ctx context.Context, c Conditions, vs []*Visa, f JWTVerifier) error {
	glog.V(1).Info("CheckConditions")
	if len(c) == 0 {
		return nil
	}
	for _, clause := range c {
		if err := checkClause(ctx, clause, vs, f); err == nil {
			return nil
		}
	}
	return fmt.Errorf("insufficient visas")
}

// Clause is an AND of Literals.
type Clause []Condition

// Literal is a Condition.
type Literal = Condition

func checkClause(ctx context.Context, c Clause, vs []*Visa, f JWTVerifier) error {
	glog.V(1).Info("checkClause")
	for _, literal := range c {
		if err := checkLiteral(ctx, literal, vs, f); err != nil {
			return err
		}
	}
	return nil
}

func checkLiteral(ctx context.Context, l Literal, vs []*Visa, f JWTVerifier) error {
	glog.V(1).Info("checkLiteral")
	for _, v := range vs {
		if err := CheckCondition(l, v.Data().Assertion); err != nil {
			glog.V(1).Infof("CheckCondition failed: %v", err)
			continue
		}
		if err := f(ctx, string(v.JWT())); err != nil {
			glog.V(1).Infof("JWT verification failed: %v", err)
			continue
		}
		return nil
	}
	return fmt.Errorf("insufficient visas")
}

// Condition represnet a GA4GH Passport Visa Condition.
// http://bit.ly/ga4gh-passport-v1#conditions
type Condition struct {
	// Type http://bit.ly/ga4gh-passport-v1#type
	Type Type `json:"type,omitempty"`

	// Value http://bit.ly/ga4gh-passport-v1#pattern-matching
	Value Pattern `json:"value,omitempty"`

	// Source http://bit.ly/ga4gh-passport-v1#source
	Source Pattern `json:"source,omitempty"`

	// By http://bit.ly/ga4gh-passport-v1#by
	By Pattern `json:"by,omitempty"`
}

// CheckCondition checks if a Visa satisfies a Condition.
// We use Visa because we would also need to verify the Visa.
// https://bit.ly/ga4gh-passport-v1#conditions
func CheckCondition(c Condition, a Assertion) error {
	glog.V(1).Info("CheckCondition")
	if c.Type == "" {
		return fmt.Errorf("Condition must specifiy Type")
	}
	if c.Type != a.Type {
		return fmt.Errorf("Type mismatch: %q %q", c.Type, a.Type)
	}

	if err := MatchPatterns(Pattern(c.By), string(a.By)); err != nil {
		return fmt.Errorf("By mismatch: %v", err)
	}

	if err := MatchPatterns(c.Source, string(a.Source)); err != nil {
		return fmt.Errorf("Source mismatch: %v", err)
	}

	if err := MatchPatterns(c.Value, string(a.Value)); err != nil {
		return fmt.Errorf("Value mismatch: %v", err)
	}

	return nil
}

func toConditionsProto(c Conditions) []*cpb.ConditionSet {
	if len(c) == 0 {
		return nil
	}
	out := []*cpb.ConditionSet{}
	for _, cor := range c {
		cs := &cpb.ConditionSet{
			AllOf: []*cpb.Condition{},
		}
		for _, cand := range cor {
			clause := &cpb.Condition{
				Type:   string(cand.Type),
				Source: string(cand.Source),
				Value:  string(cand.Value),
				By:     string(cand.By),
			}
			cs.AllOf = append(cs.AllOf, clause)
		}
		out = append(out, cs)
	}
	return out
}

// TODO: add tests for this file.
