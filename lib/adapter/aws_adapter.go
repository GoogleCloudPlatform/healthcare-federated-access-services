// Copyright 2020 Google LLC.
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
	"time"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/aws" /* copybara-comment: aws */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds" /* copybara-comment: clouds */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/processgc" /* copybara-comment: processgc */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/srcutil" /* copybara-comment: srcutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/timeutil" /* copybara-comment: timeutil */

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
)

const (
	// AwsAdapterName is the name identifier exposed in config files.
	AwsAdapterName = "aws"
	platformName   = "aws"
)

const (
	defaultGcFrequency    = 1 * 24 * time.Hour /* 1 day */
	defaultKeysPerAccount = 2
)

// AwsAdapter is the AWS IAM adapter.
type AwsAdapter struct {
	desc      map[string]*pb.ServiceDescriptor
	warehouse *aws.AccountWarehouse
}

// NewAwsAdapter creates a new AwsAdapter.
func NewAwsAdapter(store storage.Store, awsClient aws.APIClient) (ServiceAdapter, error) {
	var msg pb.ServicesResponse
	path := adapterFilePath(AwsAdapterName)
	if err := srcutil.LoadProto(path, &msg); err != nil {
		return nil, fmt.Errorf("reading %q service descriptors from path %q: %v", aggregatorName, path, err)
	}

	ctx := context.Background()
	wh, err := aws.NewWarehouse(ctx, awsClient)
	if err != nil {
		return nil, fmt.Errorf("error creating AWS key warehouse: %v", err)
	}

	keyGC := processgc.NewKeyGC("aws_key_gc", wh, store, defaultGcFrequency, defaultKeysPerAccount, func(account *clouds.Account) bool {
		return true
	})
	//Register Accounts
	if err := registerAccountGC(store, keyGC, wh); err != nil {
		return nil, fmt.Errorf("error registering AWS account key GC: %v", err)
	}

	// Update Settings
	ttl := defaultGcFrequency
	if err := keyGC.UpdateSettings(ttl, defaultKeysPerAccount, nil); err != nil {
		return nil, fmt.Errorf("error updating settings: %v", err)
	}
	go keyGC.Run(ctx)

	return &AwsAdapter{
		desc:      msg.Services,
		warehouse: wh,
	}, nil
}

// Name returns the name identifier of the adapter as used in configurations.
func (a *AwsAdapter) Name() string {
	return AwsAdapterName
}

// Descriptors returns a map of ServiceDescriptor descriptor.
func (a *AwsAdapter) Descriptors() map[string]*pb.ServiceDescriptor {
	return a.desc
}

// Platform returns the name identifier of the platform on which this adapter operates.
func (a *AwsAdapter) Platform() string {
	return platformName
}

// IsAggregator returns true if this adapter requires TokenAction.Aggregates.
func (a *AwsAdapter) IsAggregator() bool {
	return false
}

// CheckConfig validates that a new configuration is compatible with this adapter.
func (a *AwsAdapter) CheckConfig(templateName string, template *pb.ServiceTemplate, resName, viewName string, view *pb.View, cfg *pb.DamConfig, adapters *ServiceAdapters) (string, error) {
	if view == nil {
		return "", nil
	}
	if len(view.Items) == 1 {
		vars, path, err := GetItemVariables(adapters, template.ServiceName, view.Items[0])
		if err != nil {
			return httputils.StatusPath("resources", resName, "views", viewName, "items", "0", path), err
		}
		if template.ServiceName == aws.S3ItemFormat {
			if vars["bucket"] == "" {
				return httputils.StatusPath("resources", resName, "views", viewName, "items", "0", "vars", "bucket"), fmt.Errorf("no bucket specified")
			}
		} else if template.ServiceName == aws.RedshiftItemFormat {
			if vars["cluster"] == "" {
				return httputils.StatusPath("resources", resName, "views", viewName, "items", "0", "vars", "cluster"), fmt.Errorf("no cluster specified")
			}
		} else if template.ServiceName != aws.RedshiftConsoleItemFormat {
			return httputils.StatusPath("serviceTemplates", templateName, "serviceName", template.ServiceName), fmt.Errorf("invalid service name: %s", template.ServiceName)
		}
	}
	if len(view.Items) > 1 {
		return httputils.StatusPath("resources", resName, "views", viewName, "items"), fmt.Errorf("more than one item is declared for the view %q", viewName)
	}
	return "", nil
}

// MintToken has the adapter mint a token.
func (a *AwsAdapter) MintToken(ctx context.Context, input *Action) (*MintTokenResult, error) {
	if a.warehouse == nil {
		return nil, fmt.Errorf("AWS minting token: DAM service account warehouse not configured")
	}
	userID := ga4gh.TokenUserID(input.Identity, SawMaxUserIDLength)
	params, err := createAwsResourceTokenCreationParams(userID, input)
	if err != nil {
		return nil, fmt.Errorf("AWS minting token: %v", err)
	}
	result, err := a.warehouse.MintTokenWithTTL(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("AWS minting token: %v", err)
	}

	credentials := map[string]string{
		"account":   result.Account,
		"principal": result.PrincipalARN,
	}
	if result.AccessKeyID != nil {
		credentials["access_key_id"] = *result.AccessKeyID
	}
	if result.SecretAccessKey != nil {
		credentials["secret"] = *result.SecretAccessKey
	}
	if result.SessionToken != nil {
		credentials["session_token"] = *result.SessionToken
	}
	if result.UserName != nil {
		credentials["username"] = *result.UserName
	}
	if result.Password != nil {
		credentials["password"] = *result.Password
	}

	return &MintTokenResult{
		Credentials: credentials,
		TokenFormat: result.Format,
	}, nil
}

func createAwsResourceTokenCreationParams(userID string, input *Action) (*aws.ResourceParams, error) {
	var roles []string
	var scopes []string
	if input.ServiceRole != nil {
		rolesArg := input.ServiceRole.ServiceArgs["roles"]
		if rolesArg != nil && rolesArg.GetValues() != nil && len(rolesArg.GetValues()) > 0 {
			roles = append(roles, rolesArg.GetValues()...)
		}
		scopesArg := input.ServiceRole.ServiceArgs["scopes"]
		if scopesArg != nil && scopesArg.GetValues() != nil && len(scopesArg.GetValues()) > 0 {
			scopes = append(scopes, scopesArg.GetValues()...)
		}
	}
	var vars map[string]string
	if len(input.View.Items) == 0 {
		vars = make(map[string]string, 0)
	} else if len(input.View.Items) == 1 {
		vars = scrubVars(input.View.Items[0].Args)
	} else {
		return nil, fmt.Errorf("too many items declared")
	}
	maxKeyTTL := timeutil.ParseDurationWithDefault(input.Config.Options.GcpManagedKeysMaxRequestedTtl, input.MaxTTL)

	return &aws.ResourceParams{
		UserID:                userID,
		TTL:                   input.TTL,
		MaxKeyTTL:             maxKeyTTL,
		ManagedKeysPerAccount: int(input.Config.Options.GcpManagedKeysPerAccount),
		Vars:                  vars,
		TargetRoles:           roles,
		TargetScopes:          scopes,
		DamResourceID:         input.ResourceID,
		DamViewID:             input.ViewID,
		DamRoleID:             input.GrantRole,
		DamInterfaceID:        input.Interface,
		ServiceTemplate:       input.ServiceTemplate,
	}, nil
}

func registerAccountGC(_ storage.Store, keyGC *processgc.KeyGC, wh *aws.AccountWarehouse) error {
	_, err := keyGC.RegisterWork(wh.GetAwsAccount(), nil, nil)
	return err
}
