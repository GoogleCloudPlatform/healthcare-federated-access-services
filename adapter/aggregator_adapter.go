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
	"fmt"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/clouds"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/storage"

	pb "google3/third_party/hcls_federated_access/dam/api/v1/v1"
)

const (
	aggregatorName = "aggregator"
)

// AggregatorAdapter combines views from other adapters.
type AggregatorAdapter struct {
	desc       *pb.TargetAdapter
	sawAdapter Adapter
}

// NewAggregatorAdapter creates a AggregatorAdapter.
func NewAggregatorAdapter(store storage.StorageInterface, warehouse clouds.ResourceTokenCreator, secrets *pb.DamSecrets, adapters *TargetAdapters) (Adapter, error) {
	var desc pb.TargetAdapter
	if err := store.Read(AdapterDataType, storage.DefaultRealm, aggregatorName, storage.LatestRev, &desc); err != nil {
		return nil, fmt.Errorf("reading %q descriptor: %v", aggregatorName, err)
	}
	sawAdapter, ok := adapters.ByName[SawAdapterName]
	if !ok {
		return nil, fmt.Errorf("SAW adapter %q not available at time of view aggregator adapter initialization", SawAdapterName)
	}
	return &AggregatorAdapter{
		desc:       &desc,
		sawAdapter: sawAdapter,
	}, nil
}

// Name returns the name identifier of the adapter as used in configurations.
func (a *AggregatorAdapter) Name() string {
	return "token:aggregate:view"
}

// Descriptor returns a TargetAdapter descriptor.
func (a *AggregatorAdapter) Descriptor() *pb.TargetAdapter {
	return a.desc
}

// IsAggregator returns true if this adapter requires TokenAction.Aggregates.
func (a *AggregatorAdapter) IsAggregator() bool {
	return true
}

// CheckConfig validates that a new configuration is compatible with this adapter.
func (a *AggregatorAdapter) CheckConfig(templateName string, template *pb.ServiceTemplate, viewName string, view *pb.View, cfg *pb.DamConfig, adapters *TargetAdapters) error {
	if view != nil && len(view.Items) == 0 {
		return fmt.Errorf("view %q has no items defined", viewName)
	}
	if view == nil {
		return nil
	}
	adapterName := ""
	for iIdx, item := range view.Items {
		vars, err := GetItemVariables(adapters, template.TargetAdapter, template.ItemFormat, item)
		if err != nil {
			return fmt.Errorf("view %q item %d: %v", viewName, iIdx, err)
		}
		refRes, ok := cfg.Resources[vars["resource"]]
		if !ok {
			return fmt.Errorf("view %q item %d: resource not found", viewName, iIdx)
		}
		refView, ok := refRes.Views[vars["view"]]
		if !ok {
			return fmt.Errorf("view %q item %d: view not found", viewName, iIdx)
		}
		refSt, ok := cfg.ServiceTemplates[refView.ServiceTemplate]
		if !ok {
			return fmt.Errorf("view %q item %d: view service template %q not found", viewName, iIdx, refView.ServiceTemplate)
		}
		if len(adapterName) == 0 {
			adapterName = refSt.TargetAdapter
		} else if adapterName != refSt.TargetAdapter {
			return fmt.Errorf("view %q item %d: service template %q target adapter %q is not consistent with other items using target adapter %q", viewName, iIdx, refView.ServiceTemplate, refSt.TargetAdapter, adapterName)
		}
	}
	if adapterName == "" {
		return fmt.Errorf("included views offer no items to aggregate")
	}
	destAdapter, ok := adapters.Descriptors[adapterName]
	if !ok {
		return fmt.Errorf("target adapter %q not found as used within grants", adapterName)
	}
	if !destAdapter.Properties.CanBeAggregated {
		return fmt.Errorf("aggregation on target adapter %q not supported", adapterName)
	}
	return nil
}

// MintToken has the adapter mint a token and return <account>, <token>, error.
func (a *AggregatorAdapter) MintToken(input *Action) (string, string, error) {
	var acct, token string
	for _, entry := range input.Aggregates {
		action := *input
		action.ServiceTemplate = input.Config.ServiceTemplates[entry.View.ServiceTemplate]
		vsRole, err := ResolveServiceRole(input.GrantRole, entry.View, entry.Res, input.Config)
		if err != nil {
			return "", "", err
		}
		action.ServiceRole = vsRole
		acct, token, err = a.sawAdapter.MintToken(&action)
		if err != nil {
			return "", "", fmt.Errorf("aggregator minting token on item %d resource view: %v", entry.Index, err)
		}
	}
	return acct, token, nil
}
