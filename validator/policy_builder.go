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

package validator

import (
	"context"
	"fmt"
	"regexp"

	cfg "github.com/GoogleCloudPlatform/healthcare-federated-access-services/dam/api/v1"
)

func BuildPolicyValidator(ctx context.Context, policy *cfg.Policy, defs map[string]*cfg.ClaimDefinition, sources map[string]*cfg.TrustedSource) (*Policy, error) {
	allow, err := policyValidator(ctx, policy.Allow, defs, sources)
	if err != nil {
		return nil, err
	}
	disallow, err := policyValidator(ctx, policy.Disallow, defs, sources)
	if err != nil {
		return nil, err
	}
	return NewPolicy(allow, disallow), nil
}

func policyValidator(ctx context.Context, c *cfg.Condition, defs map[string]*cfg.ClaimDefinition, sources map[string]*cfg.TrustedSource) (Validator, error) {
	if c == nil {
		return nil, nil
	}
	if err := ValidateCondition(c, defs); err != nil {
		return nil, err
	}
	if len(c.AllTrue) == 1 {
		return policyValidator(ctx, c.AllTrue[0], defs, sources)
	}
	if len(c.AllTrue) > 1 {
		var vs []Validator
		for _, ce := range c.AllTrue {
			entry, err := policyValidator(ctx, ce, defs, sources)
			if err != nil {
				return nil, err
			}
			vs = append(vs, entry)
		}
		return And(vs), nil
	}
	if len(c.AnyTrue) == 1 {
		return policyValidator(ctx, c.AnyTrue[0], defs, sources)
	}
	if len(c.AnyTrue) > 1 {
		var vs []Validator
		for _, ce := range c.AnyTrue {
			entry, err := policyValidator(ctx, ce, defs, sources)
			if err != nil {
				return nil, err
			}
			vs = append(vs, entry)
		}
		return Or(vs), nil
	}
	switch k := c.Key.(type) {
	case *cfg.Condition_Claim:
		src, err := expandSources(k.Claim, c.From, sources)
		if err != nil {
			return nil, err
		}
		return NewClaimValidator(k.Claim, c.Values, c.Is, src, byMap(c.By))
	case *cfg.Condition_DataUse:
		// TODO(cdvoisin): implement this and deal with policy complexity with multiple DU values.
		return &Constant{OK: true}, nil
	}
	return nil, fmt.Errorf("condition requires one of claim, dataUse, userList, allTrue, anyTrue: %v", c)
}

func expandSources(claim string, from []string, sources map[string]*cfg.TrustedSource) (map[string]bool, error) {
	out := make(map[string]bool)
	for _, f := range from {
		source, ok := sources[f]
		if !ok {
			return nil, fmt.Errorf("from %q name is not a valid source name", f)
		}
		for _, src := range source.Sources {
			out[src] = true
		}
	}
	if len(from) == 0 {
		for sname, source := range sources {
			incl := false
			if len(source.Claims) == 0 {
				incl = true
			} else {
				for cidx, c := range source.Claims {
					if len(c) > 1 && c[0] == '^' {
						// Regexp
						re, err := regexp.Compile(c)
						if err != nil {
							return nil, fmt.Errorf("source %q claim %d invalid regular expression %q: %v", sname, cidx, c, err)
						}
						if re.Match([]byte(claim)) {
							incl = true
							break
						}
					} else if c == claim {
						incl = true
						break
					}
				}
			}
			if !incl {
				continue
			}
			for _, src := range source.Sources {
				out[src] = true
			}
		}
	}
	return out, nil
}

func byMap(strs []string) map[string]bool {
	out := make(map[string]bool)
	for _, str := range strs {
		out[str] = true
	}
	return out
}

func ValidateCondition(c *cfg.Condition, defs map[string]*cfg.ClaimDefinition) error {
	n := 0
	if len(c.AllTrue) > 0 {
		n++
	}
	if len(c.AnyTrue) > 0 {
		n++
	}
	du := false
	claim := ""
	switch k := c.Key.(type) {
	case *cfg.Condition_Claim:
		claim = k.Claim
		n++
	case *cfg.Condition_DataUse:
		du = true
		n++
	}
	if n == 0 {
		return fmt.Errorf("must specify one of [claim, dataUse, allTrue, anyTrue] in condition: %v", *c)
	}
	if n > 1 {
		return fmt.Errorf("must specify only one of [claim, dataUse, allTrue, anyTrue] in condition: %v", *c)
	}
	n = 0
	st := false
	if len(c.Values) > 0 {
		st = true
		n++
	}
	if n > 0 && (len(c.AllTrue) > 0 || len(c.AnyTrue) > 0) {
		return fmt.Errorf("cannot specify a value within scope of a allTrue or anyTrue list of clauses: %v", *c)
	}
	if du && st {
		return fmt.Errorf("cannot specify a value with a dataUse: %v", *c)
	}
	if _, ok := defs[claim]; !ok && len(claim) > 0 {
		return fmt.Errorf("claim %q is undefined in claimDefinitions: %v", claim, *c)
	}
	return nil
}
