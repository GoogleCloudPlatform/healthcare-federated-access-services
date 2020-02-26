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

package adapter

import (
	"context"
	"fmt"
	"strconv"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds" /* copybara-comment: clouds */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/srcutil" /* copybara-comment: srcutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
)

const (
	aggregatorName = "aggregator"
)

// AggregatorAdapter combines views from other adapters.
type AggregatorAdapter struct {
	desc       map[string]*pb.ServiceDescriptor
	sawAdapter ServiceAdapter
}

// NewAggregatorAdapter creates a AggregatorAdapter.
func NewAggregatorAdapter(store storage.Store, warehouse clouds.ResourceTokenCreator, secrets *pb.DamSecrets, adapters *ServiceAdapters) (ServiceAdapter, error) {
	var msg pb.ServicesResponse
	path := adapterFilePath(aggregatorName)
	if err := srcutil.LoadProto(path, &msg); err != nil {
		return nil, fmt.Errorf("reading %q service descriptors from path %q: %v", aggregatorName, path, err)
	}
	sawAdapter, ok := adapters.ByAdapterName[SawAdapterName]
	if !ok {
		return nil, fmt.Errorf("SAW adapter %q not available at time of view aggregator adapter initialization", SawAdapterName)
	}
	return &AggregatorAdapter{
		desc:       msg.Services,
		sawAdapter: sawAdapter,
	}, nil
}

// Name returns the name identifier of the adapter as used in configurations.
func (a *AggregatorAdapter) Name() string {
	return "token:aggregate:view"
}

// Platform returns the name identifier of the platform on which this adapter operates.
func (a *AggregatorAdapter) Platform() string {
	return a.sawAdapter.Platform()
}

// Descriptors returns a map of Service descriptors.
func (a *AggregatorAdapter) Descriptors() map[string]*pb.ServiceDescriptor {
	return a.desc
}

// IsAggregator returns true if this adapter requires TokenAction.Aggregates.
func (a *AggregatorAdapter) IsAggregator() bool {
	return true
}

// CheckConfig validates that a new configuration is compatible with this adapter.
func (a *AggregatorAdapter) CheckConfig(templateName string, template *pb.ServiceTemplate, resName, viewName string, view *pb.View, cfg *pb.DamConfig, adapters *ServiceAdapters) (string, error) {
	if view == nil {
		return "", nil
	}
	if len(view.Items) == 0 {
		return httputil.StatusPath("resources", resName, "views", viewName, "items"), fmt.Errorf("view %q has no items defined", viewName)
	}
	adapterName := ""
	adapterST := ""
	for iIdx, item := range view.Items {
		vars, path, err := GetItemVariables(adapters, template.ServiceName, item)
		if err != nil {
			return httputil.StatusPath("resources", resName, "views", viewName, "items", strconv.Itoa(iIdx), path), err
		}
		refResName := vars["resource"]
		refRes, ok := cfg.Resources[refResName]
		if !ok {
			return httputil.StatusPath("resources", resName, "views", viewName, "items", strconv.Itoa(iIdx), "vars", "resource"), fmt.Errorf("resource %q not found", refResName)
		}
		refViewName := vars["view"]
		refView, ok := refRes.Views[refViewName]
		if !ok {
			return httputil.StatusPath("resources", resName, "views", viewName, "items", strconv.Itoa(iIdx), "vars", "view"), fmt.Errorf("view %q not found", refViewName)
		}
		refSt, ok := cfg.ServiceTemplates[refView.ServiceTemplate]
		if !ok {
			return httputil.StatusPath("resources", refResName, "views", refViewName, "serviceTemplate"), fmt.Errorf("view service template %q not found", refView.ServiceTemplate)
		}
		adapt, ok := adapters.ByServiceName[refSt.ServiceName]
		if !ok {
			return httputil.StatusPath("resources", refResName, "views", refViewName, "serviceTemplate"), fmt.Errorf("view service name %q not defined", refSt.ServiceName)
		}
		if len(adapterName) == 0 {
			adapterName = adapt.Name()
			adapterST = refView.ServiceTemplate
		} else if adapterName != adapt.Name() {
			return httputil.StatusPath("resources", resName, "views", viewName, "items", strconv.Itoa(iIdx), "vars", "view"), fmt.Errorf("view service template %q service adapter %q does not match other items using service adapter %q", refView.ServiceTemplate, refSt.ServiceName, adapterName)
		}
		desc, ok := adapters.Descriptors[refSt.ServiceName]
		if !ok || desc == nil || desc.Properties == nil {
			return httputil.StatusPath("serviceTemplates", adapterST, "serviceName", refSt.ServiceName), fmt.Errorf("lookup of descriptor properties for %q on adapter %q failed: desc:\n%+v", refSt.ServiceName, adapterName, desc)
		}
		if !desc.Properties.CanBeAggregated {
			return httputil.StatusPath("serviceTemplates", adapterST, "targetService", "properties", "canBeAggregated"), fmt.Errorf("aggregation on service adapter %q not supported", adapterName)
		}
	}
	if adapterName == "" {
		return httputil.StatusPath("resources", resName, "views", viewName, "items"), fmt.Errorf("included views offer no items to aggregate")
	}
	return "", nil
}

// MintToken has the adapter mint a token.
func (a *AggregatorAdapter) MintToken(ctx context.Context, input *Action) (*MintTokenResult, error) {
	var result *MintTokenResult
	for _, entry := range input.Aggregates {
		action := *input
		action.ServiceTemplate = input.Config.ServiceTemplates[entry.View.ServiceTemplate]
		vsRole, err := ResolveServiceRole(input.GrantRole, entry.View, entry.Res, input.Config)
		if err != nil {
			return nil, err
		}
		action.ServiceRole = vsRole
		result, err = a.sawAdapter.MintToken(ctx, &action)
		if err != nil {
			return nil, fmt.Errorf("aggregator minting token on item %d resource view: %v", entry.Index, err)
		}
	}
	return result, nil
}
