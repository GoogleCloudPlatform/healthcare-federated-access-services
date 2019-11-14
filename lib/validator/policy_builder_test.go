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
	"testing"

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1"
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1"
)

func TestValidatePolicy(t *testing.T) {
	tests := []struct {
		name   string
		policy *pb.Policy
		args   map[string]string
	}{
		{
			name:   "empty policy",
			policy: &pb.Policy{},
		},
		{
			name: "no-op policy",
			policy: &pb.Policy{
				AnyOf: []*cpb.ConditionSet{{AllOf: []*cpb.Condition{{
					Type: "VisaType1",
				}}}},
			},
		},
		{
			name: "standard policy",
			policy: &pb.Policy{
				AnyOf: []*cpb.ConditionSet{{AllOf: []*cpb.Condition{{
					Type:   "VisaType1",
					Value:  "const:foo",
					Source: "split_pattern:SourceGroup1;SourceGroup2",
					By:     "const:dac",
				}}}},
			},
		},
		{
			name: "variable policy",
			policy: &pb.Policy{
				AnyOf: []*cpb.ConditionSet{{AllOf: []*cpb.Condition{{
					Type:   "VisaType1",
					Value:  "const:foo${BAR}",
					Source: "split_pattern:SourceGroup1;SourceGroup2",
					By:     "const:dac",
				}}}},
				VariableDefinitions: map[string]*pb.VariableFormat{
					"BAR": &pb.VariableFormat{
						Regexp: "^ba.$",
						Ui: map[string]string{
							"description": "Bar",
						},
					},
				},
			},
		},
		{
			name: "variable instance",
			policy: &pb.Policy{
				AnyOf: []*cpb.ConditionSet{{AllOf: []*cpb.Condition{{
					Type:   "VisaType1",
					Value:  "const:foo${BAR}",
					Source: "split_pattern:SourceGroup1;SourceGroup2",
					By:     "const:dac",
				}}}},
				VariableDefinitions: map[string]*pb.VariableFormat{
					"BAR": &pb.VariableFormat{
						Regexp: "^ba.$",
						Ui: map[string]string{
							"description": "Bar",
						},
					},
				},
			},
			args: map[string]string{
				"BAR": "bar",
			},
		},
	}
	defs := map[string]*pb.ClaimDefinition{
		"VisaType1": &pb.ClaimDefinition{},
	}
	sources := map[string]*pb.TrustedSource{
		"SourceGroup1": &pb.TrustedSource{
			Sources: []string{"source1.1", "source1.2"},
		},
		"SourceGroup2": &pb.TrustedSource{
			Sources: []string{"source2.1", "source2.2"},
		},
	}

	for _, tc := range tests {
		if path, err := ValidatePolicy(tc.policy, defs, sources, tc.args); err != nil {
			t.Errorf("test case %q: ValidatePolicy(%+v, defs, sources, %+v) = (%q, %v) unexpected error", tc.name, tc.policy, tc.args, path, err)
		}
	}
}

func TestValidatePolicyErrors(t *testing.T) {
	tests := []struct {
		name   string
		policy *pb.Policy
		args   map[string]string
	}{
		{
			name: "undefined visa type",
			policy: &pb.Policy{
				AnyOf: []*cpb.ConditionSet{{AllOf: []*cpb.Condition{{
					Type: "BadVisaType",
				}}}},
			},
		},
		{
			name: "missing visa type",
			policy: &pb.Policy{
				AnyOf: []*cpb.ConditionSet{{AllOf: []*cpb.Condition{{
					Value: "const:hello",
				}}}},
			},
		},
		{
			name: "undefined pattern",
			policy: &pb.Policy{
				AnyOf: []*cpb.ConditionSet{{AllOf: []*cpb.Condition{{
					Type:  "VisaType1",
					Value: "constant:foo",
				}}}},
			},
		},
		{
			name: "missing pattern",
			policy: &pb.Policy{
				AnyOf: []*cpb.ConditionSet{{AllOf: []*cpb.Condition{{
					Type:  "VisaType1",
					Value: "foo",
				}}}},
			},
		},
		{
			name: "undefined source",
			policy: &pb.Policy{
				AnyOf: []*cpb.ConditionSet{{AllOf: []*cpb.Condition{{
					Type:   "VisaType1",
					Value:  "const:foo",
					Source: "split_pattern:SourceGroup1;BadSourceGroup",
					By:     "const:dac",
				}}}},
			},
		},
		{
			name: "undefined variable (no args)",
			policy: &pb.Policy{
				AnyOf: []*cpb.ConditionSet{{AllOf: []*cpb.Condition{{
					Type:   "VisaType1",
					Value:  "const:foo${BAR}",
					Source: "split_pattern:SourceGroup1;SourceGroup2",
					By:     "const:dac",
				}}}},
			},
		},
		{
			name: "undefined variable (with args)",
			policy: &pb.Policy{
				AnyOf: []*cpb.ConditionSet{{AllOf: []*cpb.Condition{{
					Type:   "VisaType1",
					Value:  "const:foo${BAR}",
					Source: "split_pattern:SourceGroup1;SourceGroup2",
					By:     "const:dac",
				}}}},
			},
			args: map[string]string{
				"BAR": "bar",
			},
		},
		{
			name: "missing variable regex",
			policy: &pb.Policy{
				AnyOf: []*cpb.ConditionSet{{AllOf: []*cpb.Condition{{
					Type:   "VisaType1",
					Value:  "const:foo${BAR}",
					Source: "split_pattern:SourceGroup1;SourceGroup2",
					By:     "const:dac",
				}}}},
				VariableDefinitions: map[string]*pb.VariableFormat{
					"BAR": &pb.VariableFormat{
						Ui: map[string]string{
							"description": "Bar",
						},
					},
				},
			},
		},
		{
			name: "bad variable regex",
			policy: &pb.Policy{
				AnyOf: []*cpb.ConditionSet{{AllOf: []*cpb.Condition{{
					Type:   "VisaType1",
					Value:  "const:foo${BAR}",
					Source: "split_pattern:SourceGroup1;SourceGroup2",
					By:     "const:dac",
				}}}},
				VariableDefinitions: map[string]*pb.VariableFormat{
					"BAR": &pb.VariableFormat{
						Regexp: "b[^",
						Ui: map[string]string{
							"description": "Bar",
						},
					},
				},
			},
		},
		{
			name: "missing variable UI description",
			policy: &pb.Policy{
				AnyOf: []*cpb.ConditionSet{{AllOf: []*cpb.Condition{{
					Type:   "VisaType1",
					Value:  "const:foo${BAR}",
					Source: "split_pattern:SourceGroup1;SourceGroup2",
					By:     "const:dac",
				}}}},
				VariableDefinitions: map[string]*pb.VariableFormat{
					"BAR": &pb.VariableFormat{
						Regexp: "b{",
					},
				},
			},
		},
		{
			name: "variable format mismatch",
			policy: &pb.Policy{
				AnyOf: []*cpb.ConditionSet{{AllOf: []*cpb.Condition{{
					Type:  "VisaType1",
					Value: "const:foo${BAR}",
				}}}},
				VariableDefinitions: map[string]*pb.VariableFormat{
					"BAR": &pb.VariableFormat{
						Regexp: "^ba.$",
						Ui: map[string]string{
							"description": "Bar",
						},
					},
				},
			},
			args: map[string]string{
				"BAR": "but",
			},
		},
	}
	defs := map[string]*pb.ClaimDefinition{
		"VisaType1": &pb.ClaimDefinition{},
	}
	sources := map[string]*pb.TrustedSource{
		"SourceGroup1": &pb.TrustedSource{
			Sources: []string{"source1.1", "source1.2"},
		},
		"SourceGroup2": &pb.TrustedSource{
			Sources: []string{"source2.1", "source2.2"},
		},
	}
	for _, tc := range tests {
		if got, err := ValidatePolicy(tc.policy, defs, sources, tc.args); err == nil {
			t.Errorf("test case %q: ValidatePolicy(%+v, defs, sources, %+v) = (%q, %v), want (_, error)", tc.name, tc.policy, tc.args, got, err)
		}
	}
}
