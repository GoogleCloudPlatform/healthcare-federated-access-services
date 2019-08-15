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

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage"

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1"
)

const (
	// SawAdapterName is the name identifier exposed in config files.
	SawAdapterName = "token:gcp:sa"
	sawName        = "saw"
	// SawMaxUserIDLength is the service account desc max length.
	SawMaxUserIDLength = 100
)

// SawAdapter is a Service Account Warehouse (SAW) adapter.
type SawAdapter struct {
	desc      *pb.TargetAdapter
	warehouse clouds.ResourceTokenCreator
}

// NewSawAdapter creates a Service Account Warehouse (SAW) adapter.
func NewSawAdapter(store storage.Store, warehouse clouds.ResourceTokenCreator, secrets *pb.DamSecrets, adapters *TargetAdapters) (Adapter, error) {
	var desc pb.TargetAdapter
	if err := store.Read(AdapterDataType, storage.DefaultRealm, storage.DefaultUser, sawName, storage.LatestRev, &desc); err != nil {
		return nil, fmt.Errorf("reading %q descriptor: %v", sawName, err)
	}
	return &SawAdapter{
		desc:      &desc,
		warehouse: warehouse,
	}, nil
}

// Name returns the name identifier of the adapter as used in configurations.
func (a *SawAdapter) Name() string {
	return SawAdapterName
}

// Descriptor returns a TargetAdapter descriptor.
func (a *SawAdapter) Descriptor() *pb.TargetAdapter {
	return a.desc
}

// IsAggregator returns true if this adapter requires TokenAction.Aggregates.
func (a *SawAdapter) IsAggregator() bool {
	return false
}

// CheckConfig validates that a new configuration is compatible with this adapter.
func (a *SawAdapter) CheckConfig(templateName string, template *pb.ServiceTemplate, viewName string, view *pb.View, cfg *pb.DamConfig, adapters *TargetAdapters) error {
	if cfg.Options == nil || len(cfg.Options.GcpServiceAccountProject) == 0 {
		return fmt.Errorf("service template %q uses service accounts but options.gcpServiceAccountProject is not defined", templateName)
	}
	return nil
}

// MintToken has the adapter mint a token.
func (a *SawAdapter) MintToken(input *Action) (*MintTokenResult, error) {
	if a.warehouse == nil {
		return nil, fmt.Errorf("SAW minting token: DAM service account warehouse not configured")
	}
	userID := common.TokenUserID(input.Identity, SawMaxUserIDLength)
	maxKeyTTL, _ := common.ParseDuration(input.Config.Options.GcpManagedKeysMaxRequestedTtl, input.MaxTTL)
	result, err := a.warehouse.MintTokenWithTTL(input.Request.Context(), userID, input.TTL, maxKeyTTL, int(input.Config.Options.GcpManagedKeysPerAccount), resourceTokenCreationParams(input.GrantRole, input.ServiceTemplate, input.ServiceRole, input.View, input.Config, input.TokenFormat))
	if err != nil {
		return nil, fmt.Errorf("SAW minting token: %v", err)
	}
	return &MintTokenResult{
		Account:     result.Account,
		Token:       result.Token,
		TokenFormat: result.Format,
	}, nil
}

func resourceTokenCreationParams(role string, template *pb.ServiceTemplate, sRole *pb.ServiceRole, view *pb.View, cfg *pb.DamConfig, format string) *clouds.ResourceTokenCreationParams {
	roles := []string{}
	scopes := []string{}
	if sRole != nil {
		if len(sRole.TargetRoles) > 0 {
			roles = append(roles, sRole.TargetRoles...)
		}
		if len(sRole.TargetScopes) > 0 {
			scopes = append(scopes, sRole.TargetScopes...)
		}
	}
	items := make([]map[string]string, len(view.Items))
	for index, item := range view.Items {
		items[index] = scrubVars(item.Vars)
	}
	return &clouds.ResourceTokenCreationParams{
		AccountProject: cfg.Options.GcpServiceAccountProject,
		Items:          items,
		Roles:          roles,
		Scopes:         scopes,
		TokenFormat:    format,
	}
}

func scrubVars(vars map[string]string) map[string]string {
	for k, v := range vars {
		if len(v) == 0 {
			delete(vars, k)
		}
	}
	return vars
}
