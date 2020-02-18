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

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common" /* copybara-comment: common */

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
)

// contextKey is just an empty struct. It exists so RequestTTLInNanoFloat64 can be an immutable public variable with a unique type. It's immutable because nobody else can create a ContextKey, being unexported.
type contextKey struct{}

// RequestTTLInNanoFloat64 is the context key to use with golang.org/x/net/context's WithValue function to associate a "requested_ttl" value with a context.
var RequestTTLInNanoFloat64 contextKey

// valueType is the set of types which are treated like claims that have a
// value and source as sociated with them.
var valueType = map[reflect.Type]bool{
	reflect.TypeOf([]ga4gh.OldClaim{}): true,
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
	ttl, ok := ctx.Value(RequestTTLInNanoFloat64).(float64)
	if !ok {
		ttl = 0
	}
	ret := c.validate(ttl, identity)
	if c.IsNot {
		return !ret, nil
	}
	return ret, nil
}

func (c *ClaimValidator) validate(ttl float64, id *ga4gh.Identity) bool {
	tnow := time.Now()
	now := float64(tnow.Unix())
	vs, ok := id.GA4GH[c.Name]
	if !ok {
		return false
	}
	for _, v := range vs {
		if v.Asserted > now {
			id.RejectVisa(v.VisaData, v.TokenFormat, "visa_before_active", "visa.asserted", "visa is not yet active (visa.asserted is in the future)")
			continue
		}
		if v.Expires < now+ttl {
			id.RejectVisa(v.VisaData, v.TokenFormat, "visa_expired", "exp", "visa expired")
			continue
		}
		// GA4GH AAI requires that visas in AccessTokenVisaFormat need to verify their validity
		// every hour. To adhere without rechecking, will only accept these visas for one hour
		// from time of issue compared to the requested time of expiry of access (now+ttl).
		if v.TokenFormat == ga4gh.AccessTokenVisaFormat {
			requestedExpiry := tnow.Add(time.Duration(ttl * 1e9)) // ttl seconds to nano
			iat := time.Unix(v.VisaData.IssuedAt, 0)
			if requestedExpiry.Sub(iat) > time.Hour {
				id.RejectVisa(v.VisaData, v.TokenFormat, "access_token_visa_expiry", "jku", "access token visa format not supported for access more than 1 hour, use document visa format via jku instead")
				continue
			}
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
		if !match {
			id.RejectVisa(v.VisaData, v.TokenFormat, "visa_value_rejected", "visa.value", fmt.Sprintf("visa value %q not accepted by the policy", v.Value))
			continue
		}
		if len(v.Source) == 0 {
			id.RejectVisa(v.VisaData, v.TokenFormat, "visa_source_missing", "visa.source", "visa source is empty")
			continue
		}
		if len(c.Sources) > 0 {
			if _, ok := c.Sources[v.Source]; !ok {
				id.RejectVisa(v.VisaData, v.TokenFormat, "visa_source_rejected", "visa.source", fmt.Sprintf("visa source %q not accepted by the policy", v.Source))
				continue
			}
		}
		if len(c.By) > 0 {
			if _, ok := c.By[v.By]; !ok {
				id.RejectVisa(v.VisaData, v.TokenFormat, "visa_by_rejected", "visa.by", fmt.Sprintf("visa by %q not accepted by the policy", v.By))
				continue
			}
		}
		if len(v.Condition) == 0 {
			return true
		}

		match = false
		for ck, cv := range v.Condition {
			match = false
			idcList, ok := id.GA4GH[ck]
			if !ok {
				id.RejectVisa(v.VisaData, v.TokenFormat, "visa_by_rejected", "visa.by", fmt.Sprintf("visa by %q not accepted by the policy", v.By))
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
