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

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds" /* copybara-comment: clouds */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/srcutil" /* copybara-comment: srcutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/timeutil" /* copybara-comment: timeutil */

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
)

const (
	// SawAdapterName is the name identifier exposed in config files.
	SawAdapterName = "saw"
	sawPlatform    = "gcp"
	// SawMaxUserIDLength is the service account desc max length.
	SawMaxUserIDLength = 100
	sawBucketVar       = "bucket"
	sawPaysBucketVar   = "requester-pays-bucket"
)

// SawAdapter is a Service Account Warehouse (SAW) adapter.
type SawAdapter struct {
	desc      map[string]*pb.ServiceDescriptor
	warehouse clouds.ResourceTokenCreator
}

// NewSawAdapter creates a Service Account Warehouse (SAW) adapter.
func NewSawAdapter(warehouse clouds.ResourceTokenCreator) (ServiceAdapter, error) {
	var msg pb.ServicesResponse
	path := adapterFilePath(SawAdapterName)
	if err := srcutil.LoadProto(path, &msg); err != nil {
		return nil, fmt.Errorf("reading %q service descriptors from path %q: %v", aggregatorName, path, err)
	}
	return &SawAdapter{
		desc:      msg.Services,
		warehouse: warehouse,
	}, nil
}

// Name returns the name identifier of the adapter as used in configurations.
func (a *SawAdapter) Name() string {
	return SawAdapterName
}

// Platform returns the name identifier of the platform on which this adapter operates.
func (a *SawAdapter) Platform() string {
	return sawPlatform
}

// Descriptors returns a map of ServiceDescriptor descriptor.
func (a *SawAdapter) Descriptors() map[string]*pb.ServiceDescriptor {
	return a.desc
}

// IsAggregator returns true if this adapter requires TokenAction.Aggregates.
func (a *SawAdapter) IsAggregator() bool {
	return false
}

// CheckConfig validates that a new configuration is compatible with this adapter.
func (a *SawAdapter) CheckConfig(templateName string, template *pb.ServiceTemplate, resName, viewName string, view *pb.View, cfg *pb.DamConfig, adapters *ServiceAdapters) (string, error) {
	if cfg.Options == nil || len(cfg.Options.GcpServiceAccountProject) == 0 {
		return httputils.StatusPath("serviceTemplates", templateName, "targetAdapter"), fmt.Errorf("service adapter uses service accounts but options.gcpServiceAccountProject is not defined")
	}
	return "", nil
}

// MintToken has the adapter mint a token.
func (a *SawAdapter) MintToken(ctx context.Context, input *Action) (*MintTokenResult, error) {
	if a.warehouse == nil {
		return nil, fmt.Errorf("SAW minting token: DAM service account warehouse not configured")
	}
	userID := ga4gh.TokenUserID(input.Identity, SawMaxUserIDLength)
	maxKeyTTL := timeutil.ParseDurationWithDefault(input.Config.Options.GcpManagedKeysMaxRequestedTtl, input.MaxTTL)
	params, err := resourceTokenCreationParams(input.GrantRole, input.ServiceTemplate, input.ServiceRole, input.View, input.Config, input.TokenFormat)
	if err != nil {
		return nil, fmt.Errorf("SAW minting token: %v", err)
	}
	result, err := a.warehouse.MintTokenWithTTL(ctx, userID, input.TTL, maxKeyTTL, int(input.Config.Options.GcpManagedKeysPerAccount), params)
	if err != nil {
		return nil, fmt.Errorf("SAW minting token: %v", err)
	}
	res := &MintTokenResult{
		Credentials: map[string]string{
			"account": result.Account,
		},
		TokenFormat: result.Format,
	}

	if len(result.Token) > 0 {
		res.Credentials["access_token"] = result.Token
	}
	if len(result.AccountKey) > 0 {
		res.Credentials["service_account_key"] = result.AccountKey
	}

	return res, nil
}

func resourceTokenCreationParams(role string, template *pb.ServiceTemplate, sRole *pb.ServiceRole, view *pb.View, cfg *pb.DamConfig, format string) (*clouds.ResourceTokenCreationParams, error) {
	roles := []string{}
	scopes := []string{"https://www.googleapis.com/auth/cloud-platform"}
	if sRole != nil {
		if arg, ok := sRole.ServiceArgs["roles"]; ok {
			roles = arg.Values
		}
		if arg, ok := sRole.ServiceArgs["scopes"]; ok {
			scopes = arg.Values
		}
	}
	items := make([]map[string]string, len(view.Items))
	for index, item := range view.Items {
		items[index] = scrubVars(item.Args)
	}
	billingProject := cfg.Options.GcpIamBillingProject
	if len(billingProject) == 0 {
		billingProject = cfg.Options.GcpServiceAccountProject
	}
	return &clouds.ResourceTokenCreationParams{
		AccountProject: cfg.Options.GcpServiceAccountProject,
		Items:          items,
		Roles:          roles,
		Scopes:         scopes,
		TokenFormat:    format,
		BillingProject: billingProject,
	}, nil
}

func scrubVars(vars map[string]string) map[string]string {
	for k, v := range vars {
		if len(v) == 0 {
			delete(vars, k)
		}
	}
	return vars
}
