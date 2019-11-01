package adapter

import (
	"context"
	"fmt"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/aws"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage"
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1"
)

const (
	AwsAdapterName = "token:aws:iam"
    Aws = "aws"
)

type AwsAdapter struct {
	desc      *pb.TargetAdapter
	warehouse *aws.AccountWarehouse
}

func NewAwsAdapter(store storage.Store, warehouse clouds.ResourceTokenCreator, secrets *pb.DamSecrets, adapters *TargetAdapters) (Adapter, error) {
	var desc pb.TargetAdapter
	if err := store.Read(AdapterDataType, storage.DefaultRealm, storage.DefaultUser, Aws, storage.LatestRev, &desc); err != nil {
		return nil, fmt.Errorf("reading %q descriptor: %v", Aws, err)
	}
	wh, err := aws.NewWarehouse(store)
	if err != nil {
		return nil, fmt.Errorf("error creating AWS key warehouse: %v", err)
	}

	return &AwsAdapter{
		desc: &desc,
		warehouse: wh,
	}, nil
}

func (a *AwsAdapter) Name() string {
	return AwsAdapterName
}

func (a *AwsAdapter) Platform() string {
	return Aws
}

func (a *AwsAdapter) Descriptor() *pb.TargetAdapter {
	return a.desc
}

func (a *AwsAdapter) IsAggregator() bool {
	return false
}

func (a *AwsAdapter) CheckConfig(templateName string, template *pb.ServiceTemplate, resName, viewName string, view *pb.View, cfg *pb.DamConfig, adapters *TargetAdapters) (string, error) {
	return "", nil
}

func (a *AwsAdapter) MintToken(ctx context.Context, input *Action) (*MintTokenResult, error) {
	if a.warehouse == nil {
		return nil, fmt.Errorf("SAW minting token: DAM service account warehouse not configured")
	}
	userID := common.TokenUserID(input.Identity, SawMaxUserIDLength)
	params, err := createAwsResourceTokenCreationParams(userID, input)
	if err != nil {
		return nil, fmt.Errorf("SAW minting token: %v", err)
	}
	result, err := a.warehouse.MintTokenWithTTL(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("SAW minting token: %v", err)
	}
	return &MintTokenResult{
		Account:     result.Account,
		Token:       result.Token,
		TokenFormat: result.Format,
	}, nil
}

func createAwsResourceTokenCreationParams(userID string, input *Action) (*aws.ResourceParams, error) {
	var roles []string
	var scopes []string
	if input.ServiceRole != nil {
		if len(input.ServiceRole.TargetRoles) > 0 {
			roles = append(roles, input.ServiceRole.TargetRoles...)
		}
		if len(input.ServiceRole.TargetScopes) > 0 {
			scopes = append(scopes, input.ServiceRole.TargetScopes...)
		}
	}
	var vars map[string]string
	if len(input.View.Items) == 0 {
		vars = make(map[string]string, 0)
	} else if len(input.View.Items) == 1 {
		vars = scrubVars(input.View.Items[0].Vars)
	} else {
		return nil, fmt.Errorf("too many items declared")
	}
	maxKeyTtl, err := common.ParseDuration(input.Config.Options.GcpManagedKeysMaxRequestedTtl, input.MaxTTL)
	if err != nil {
		return nil, fmt.Errorf("invalid max TTL %v: %v", input.MaxTTL, err)
	}

	return &aws.ResourceParams{
		UserId:                userID,
		Ttl:                   input.TTL,
		MaxKeyTtl:             maxKeyTtl,
		ManagedKeysPerAccount: int(input.Config.Options.GcpManagedKeysPerAccount),
		Vars:                  vars,
		TargetRoles:           roles,
		TargetScopes:          scopes,
		TokenFormat:           input.TokenFormat,
		DamResourceId:         input.ResourceId,
		DamViewId:             input.ViewId,
		DamRoleId:             input.GrantRole,
		View:                  input.View,
		ServiceTemplate:       input.ServiceTemplate,
	}, nil
}
