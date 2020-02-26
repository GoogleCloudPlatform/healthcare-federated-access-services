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

// Package adapter allows the DAM to take actions.
package adapter

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds" /* copybara-comment: clouds */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/globalflags" /* copybara-comment: globalflags */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
)

const (
	// AdapterDataType is the name of adapter file types.
	AdapterDataType = "adapter"
)

// AggregateView defines an aggregated view.
type AggregateView struct {
	Index int
	Res   *pb.Resource
	View  *pb.View
}

// Action provides inputs to action methods on adapters.
type Action struct {
	Aggregates      []*AggregateView
	ClientID        string
	Config          *pb.DamConfig
	GrantRole       string
	Identity        *ga4gh.Identity
	Issuer          string
	MaxTTL          time.Duration
	Resource        *pb.Resource
	ServiceRole     *pb.ServiceRole
	ServiceTemplate *pb.ServiceTemplate
	TTL             time.Duration
	View            *pb.View
	TokenFormat     string
}

// MintTokenResult is returned by the MintToken() method.
type MintTokenResult struct {
	Account     string
	Token       string
	TokenFormat string
}

// ServiceAdapter defines the interface for all DAM adapters that take access actions.
type ServiceAdapter interface {
	// Name returns the name identifier of the adapter as used in configurations.
	Name() string

	// Platform returns the name identifier of the platform on which this adapter operates.
	Platform() string

	// Descriptor returns a service descriptor.
	Descriptor() *pb.ServiceDescriptor

	// IsAggregator returns true if this adapter requires TokenAction.Aggregates.
	IsAggregator() bool

	// CheckConfig validates that a new configuration is compatible with this adapter.
	CheckConfig(templateName string, template *pb.ServiceTemplate, resName, viewName string, view *pb.View, cfg *pb.DamConfig, adapters *ServiceAdapters) (string, error)

	// MintToken has the adapter mint a token.
	MintToken(ctx context.Context, input *Action) (*MintTokenResult, error)
}

// ServiceAdapters includes all adapters that are registered with the system.
type ServiceAdapters struct {
	ByName      map[string]ServiceAdapter
	Descriptors map[string]*pb.ServiceDescriptor
	VariableREs map[string]map[string]map[string]*regexp.Regexp // adapterName.itemFormat.variableName.regexp
	errors      []error
}

// CreateAdapters registers and collects all adapters with the system.
func CreateAdapters(store storage.Store, warehouse clouds.ResourceTokenCreator, secrets *pb.DamSecrets) (*ServiceAdapters, error) {
	adapters := &ServiceAdapters{
		ByName:      make(map[string]ServiceAdapter),
		Descriptors: make(map[string]*pb.ServiceDescriptor),
		errors:      []error{},
	}
	registerAdapter(adapters, store, warehouse, secrets, NewSawAdapter)
	registerAdapter(adapters, store, warehouse, secrets, NewGatekeeperAdapter)
	registerAdapter(adapters, store, warehouse, secrets, NewAggregatorAdapter)

	if len(adapters.errors) > 0 {
		return nil, adapters.errors[0]
	}

	adapters.VariableREs = createVariableREs(adapters.Descriptors)

	return adapters, nil
}

// GetItemVariables returns a map of variables and their values for a given view item.
func GetItemVariables(adapters *ServiceAdapters, ServiceAdapter, itemFormat string, item *pb.View_Item) (map[string]string, string, error) {
	adapter, ok := adapters.Descriptors[ServiceAdapter]
	if !ok {
		return nil, httputil.StatusPath("ServiceAdapter"), fmt.Errorf("target adapter %q is undefined", ServiceAdapter)
	}
	format, ok := adapter.ItemFormats[itemFormat]
	if !ok {
		return nil, httputil.StatusPath("itemFormats", itemFormat), fmt.Errorf("target adapter %q item format %q is undefined", ServiceAdapter, itemFormat)
	}
	for varname, val := range item.Args {
		v, ok := format.Variables[varname]
		if !ok {
			return nil, httputil.StatusPath("vars", varname), fmt.Errorf("target adapter %q item format %q variable %q is undefined", ServiceAdapter, itemFormat, varname)
		}
		if !globalflags.Experimental && v.Experimental {
			return nil, httputil.StatusPath("vars", varname), fmt.Errorf("target adapter %q item format %q variable %q is for experimental use only, not for use in this environment", ServiceAdapter, itemFormat, varname)
		}
		if len(val) == 0 {
			// Treat empty input the same as not provided so long as the variable name is valid.
			delete(item.Args, varname)
			continue
		}
		re, ok := adapters.VariableREs[ServiceAdapter][itemFormat][varname]
		if !ok {
			continue
		}
		if !re.Match([]byte(val)) {
			return nil, httputil.StatusPath("vars", varname), fmt.Errorf("target adapter %q item format %q variable %q value %q does not match expected regexp", ServiceAdapter, itemFormat, varname, val)
		}
	}
	return item.Args, "", nil
}

// ResolveServiceRole is a helper function that returns a ServiceRole structure from a role name on a view.
func ResolveServiceRole(roleName string, view *pb.View, res *pb.Resource, cfg *pb.DamConfig) (*pb.ServiceRole, error) {
	st, ok := cfg.ServiceTemplates[view.ServiceTemplate]
	if !ok {
		return nil, fmt.Errorf("internal reference to service template %q not found", view.ServiceTemplate)
	}
	sRole, ok := st.ServiceRoles[roleName]
	if !ok {
		return nil, fmt.Errorf("internal reference to service template %q role %q not found", view.ServiceTemplate, roleName)
	}
	return sRole, nil
}

func registerAdapter(adapters *ServiceAdapters, store storage.Store, warehouse clouds.ResourceTokenCreator, secrets *pb.DamSecrets, init func(storage.Store, clouds.ResourceTokenCreator, *pb.DamSecrets, *ServiceAdapters) (ServiceAdapter, error)) {
	adapter, err := init(store, warehouse, secrets, adapters)
	if err != nil {
		adapters.errors = append(adapters.errors, err)
		return
	}
	name := adapter.Name()
	adapters.ByName[name] = adapter
	adapters.Descriptors[name] = adapter.Descriptor()
}

func createVariableREs(descriptors map[string]*pb.ServiceDescriptor) map[string]map[string]map[string]*regexp.Regexp {
	// Create a compiled set of regular expressions for adapter variable formats
	// of the form: map[<adapterName>]map[<itemFormat>]map[<variableName>]*regexp.Regexp.
	varRE := make(map[string]map[string]map[string]*regexp.Regexp)
	for k, v := range descriptors {
		if len(v.ItemFormats) > 0 {
			fEntry := make(map[string]map[string]*regexp.Regexp)
			varRE[k] = fEntry
			for fk, fv := range v.ItemFormats {
				vEntry := make(map[string]*regexp.Regexp)
				fEntry[fk] = vEntry
				for vk, vv := range fv.Variables {
					if len(vv.Regexp) > 0 {
						restr := vv.Regexp
						if vv.Type == "split_pattern" {
							frag := stripAnchors(restr)
							restr = "^" + frag + "(;" + frag + ")*$"
						}
						vEntry[vk] = regexp.MustCompile(restr)
					}
				}
			}
		}
	}
	return varRE
}

func stripAnchors(restr string) string {
	if strings.HasPrefix(restr, "^") {
		restr = restr[1:]
	}
	if strings.HasSuffix(restr, "$") {
		restr = restr[0 : len(restr)-1]
	}
	return restr
}
