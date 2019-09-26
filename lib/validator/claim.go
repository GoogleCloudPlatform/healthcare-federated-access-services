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
	"reflect"
	"regexp"
	"time"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh"
)

const (
	requestTTLInNanoFloat64 = "requested_ttl"
)

// valueType is the set of types which are treated like claims that have a
// value and source as sociated with them.
var valueType = map[reflect.Type]bool{
	reflect.TypeOf([]ga4gh.Claim{}): true,
}

// ClaimValidator is a ga4gh.Validator that compares GA4GH claims.
type ClaimValidator struct {
	Name        string
	ConstantMap map[string]bool
	RegexValues []*regexp.Regexp
	IsNot       bool
	Sources     map[string]bool
	By          map[string]bool
}

// NewClaimValidator creates a ClaimValidator instance.
func NewClaimValidator(name string, values []string, is string, sources map[string]bool, by map[string]bool) (*ClaimValidator, error) {
	rlist := []*regexp.Regexp{}
	constMap := make(map[string]bool)
	if len(is) > 0 && (is != "=" && is != "==" && is != "!=") {
		return nil, fmt.Errorf("claim %q is %q comparison type is undefined", name, is)
	}
	for i, v := range values {
		if len(v) == 0 {
			return nil, fmt.Errorf("claim %q value %d is an empty string", name, i)
		}
		if v[0] == '^' {
			// Treat as a regexp string.
			if v[len(v)-1] != '$' {
				return nil, fmt.Errorf("claim %q regular expression value %q is missing string terminator %q", name, v, "$")
			}
			re, err := regexp.Compile(v)
			if err != nil {
				return nil, fmt.Errorf("claim %q regular expression value %q error: %v", name, v, err)
			}
			rlist = append(rlist, re)
		} else {
			constMap[v] = true
		}
	}
	return &ClaimValidator{
		Name:        name,
		ConstantMap: constMap,
		RegexValues: rlist,
		IsNot:       is == "!=",
		Sources:     sources,
		By:          by,
	}, nil
}

func (c *ClaimValidator) Validate(ctx context.Context, identity *ga4gh.Identity) (bool, error) {
	ttl, ok := ctx.Value(requestTTLInNanoFloat64).(float64)
	if !ok {
		ttl = 0
	}
	ret := c.validate(ttl, identity)
	if c.IsNot {
		return !ret, nil
	}
	return ret, nil
}

func (c *ClaimValidator) validate(ttl float64, identity *ga4gh.Identity) bool {
	now := float64(time.Now().Unix())
	vs, ok := identity.GA4GH[c.Name]
	if !ok {
		return false
	}
	for _, v := range vs {
		if v.Asserted > now || v.Expires < now+ttl {
			continue
		}
		match := false
		if _, ok := c.ConstantMap[v.Value]; ok {
			match = true
		} else {
			bv := []byte(v.Value)
			for _, re := range c.RegexValues {
				if re.Match(bv) {
					match = true
					break
				}
			}
		}
		if !match || len(v.Source) == 0 {
			continue
		}
		if len(c.Sources) > 0 {
			if _, ok := c.Sources[v.Source]; !ok {
				continue
			}
		}
		if len(c.By) > 0 {
			if _, ok := c.By[v.By]; !ok {
				continue
			}
		}
		if len(v.Condition) == 0 {
			return true
		}

		match = false
		for ck, cv := range v.Condition {
			match = false
			idcList, ok := identity.GA4GH[ck]
			if !ok {
				continue
			}
			for _, idc := range idcList {
				if idc.Asserted > now || idc.Expires < now+ttl {
					continue
				}
				if len(cv.Value) > 0 && !common.ListContains(cv.Value, idc.Value) {
					continue
				}
				if len(cv.Source) > 0 && !common.ListContains(cv.Source, idc.Source) {
					continue
				}
				if len(cv.By) > 0 && !common.ListContains(cv.By, idc.By) {
					continue
				}
				match = true
				break
			}
			if !match {
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
