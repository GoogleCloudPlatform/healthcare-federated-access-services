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

package aws

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
	"github.com/aws/aws-sdk-go/aws"                                                       /* copybara-comment */
)

// end Mock AWS Client

func NewMockBucketParams(ttl time.Duration) *ResourceParams {
	return &ResourceParams{
		UserID:                "ic_abc123|fake-ic",
		TTL:                   ttl,
		MaxKeyTTL:             (24 * 30) * time.Hour,
		ManagedKeysPerAccount: 2,
		Vars:                  map[string]string{"bucket": "test-bucket-name"},
		TargetRoles:           []string{"s3:GetObject"},
		TargetScopes:          []string{},
		DamResourceID:         "res-id",
		DamViewID:             "view-id",
		DamRoleID:             "role-id",
		ServiceTemplate:       &pb.ServiceTemplate{ServiceName: "s3bucket"},
	}
}

func NewMockRedshiftParams(ttl time.Duration) *ResourceParams {
	vars := map[string]string{
		"cluster": "arn:aws:redshift:us-east-1:12345678:cluster:test-cluster",
		"group":   "arn:aws:redshift:us-east-1:12345678:dbgroup:test-cluster/admin",
	}
	roles := []string{
		"redshift:GetClusterCredentials",
		"redshift:CreateClusterUser",
		"redshift:JoinGroup",
	}

	return &ResourceParams{
		UserID:                "ic_abc123|fake-ic",
		TTL:                   ttl,
		MaxKeyTTL:             (24 * 30) * time.Hour,
		ManagedKeysPerAccount: 2,
		Vars:                  vars,
		TargetRoles:           roles,
		TargetScopes:          []string{},
		DamResourceID:         "res-id",
		DamViewID:             "view-id",
		DamRoleID:             "role-id",
		ServiceTemplate:       &pb.ServiceTemplate{ServiceName: "redshift"},
	}
}

func TestNewAwsWarehouse(t *testing.T) {
	apiClient := NewMockAPIClient("12345678", "dam-user-id")
	wh, err := NewWarehouse(context.Background(), apiClient)

	if err != nil {
		t.Errorf("expected no error but observed: %v", err)
	}
	if wh == nil {
		t.Errorf("expected non-nil warehouse")
	}
}

func TestAWS_MintTokenWithShortLivedTTL_Bucket(t *testing.T) {
	damPrincipalID := "dam-user-id"
	awsAccount := "12345678"
	apiClient := NewMockAPIClient(awsAccount, damPrincipalID)
	wh, _ := NewWarehouse(context.Background(), apiClient)
	params := NewMockBucketParams(time.Hour)

	result, err := wh.MintTokenWithTTL(context.Background(), params)

	expectedRoleName := fmt.Sprintf("%s,%s,%s@%s", params.DamResourceID, params.DamViewID, params.DamRoleID, damPrincipalID)
	expectedRoleArn := fmt.Sprintf("arn:aws:iam::%s:role/ddap/%s", awsAccount, expectedRoleName)
	validateMintedRoleCredentials(t, expectedRoleArn, result, err)
	validateCreatedRolePolicy(t, apiClient, expectedRoleName, params.TargetRoles)
}

func TestAWS_MintTokenWithShortLivedTTL_Redshift(t *testing.T) {
	awsAccount := "12345678"
	damPrincipalID := "dam-user-id"
	apiClient := NewMockAPIClient(awsAccount, damPrincipalID)
	wh, _ := NewWarehouse(context.Background(), apiClient)
	params := NewMockRedshiftParams(time.Hour)

	result, err := wh.MintTokenWithTTL(context.Background(), params)

	expectedRoleName := fmt.Sprintf("%s,%s,%s@%s", params.DamResourceID, params.DamViewID, params.DamRoleID, damPrincipalID)
	expectedRoleArn := fmt.Sprintf("arn:aws:iam::%s:role/ddap/%s", awsAccount, expectedRoleName)
	validateMintedRoleCredentials(t, expectedRoleArn, result, err)
	validateCreatedRolePolicy(t, apiClient, expectedRoleName, params.TargetRoles)
}

func TestAWS_MintTokenWithLongLivedTTL_Bucket(t *testing.T) {
	awsAccount := "12345678"
	damPrincipalID := "dam-user-id"
	apiClient := NewMockAPIClient(awsAccount, damPrincipalID)
	wh, _ := NewWarehouse(context.Background(), apiClient)
	// AWS has 12-hour threshold for role access tokens
	params := NewMockBucketParams(13 * time.Hour)

	result, err := wh.MintTokenWithTTL(context.Background(), params)

	expectedUserName := "ic_abc123@" + damPrincipalID
	expectedUserArn := fmt.Sprintf("arn:aws:iam::%s:user/%s", awsAccount, expectedUserName)
	validateMintedAccessKey(t, expectedUserArn, result, err)
	validateCreatedUserPolicy(t, apiClient, expectedUserName, params.TargetRoles)
}

func TestAWS_MintTokenWithLongLivedTTL_Redshift(t *testing.T) {
	awsAccount := "12345678"
	damPrincipalID := "dam-user-id"
	apiClient := NewMockAPIClient(awsAccount, damPrincipalID)
	wh, _ := NewWarehouse(context.Background(), apiClient)
	// AWS has 12-hour threshold for role access tokens
	params := NewMockRedshiftParams(13 * time.Hour)

	result, err := wh.MintTokenWithTTL(context.Background(), params)

	expectedUserName := "ic_abc123@" + damPrincipalID
	expectedUserArn := fmt.Sprintf("arn:aws:iam::%s:user/%s", awsAccount, expectedUserName)
	validateMintedAccessKey(t, expectedUserArn, result, err)
	validateCreatedUserPolicy(t, apiClient, expectedUserName, params.TargetRoles)
}

func TestAWS_ManageAccountKeys_BelowMax(t *testing.T) {
	awsAccount := "12345678"
	damPrincipalID := "dam-user-id"
	apiClient := NewMockAPIClient(awsAccount, damPrincipalID)
	wh, _ := NewWarehouse(context.Background(), apiClient)

	// AWS has 12-hour threshold for role access tokens
	params := NewMockBucketParams(13 * time.Hour)
	for i := 0; i < params.ManagedKeysPerAccount; i++ {
		_, err := wh.MintTokenWithTTL(context.Background(), params)
		if err != nil {
			t.Errorf("prerequisite failed: error minting token: %v", err)
			// no point in trying other assertions
			return
		}
	}

	expectedUserName := "ic_abc123@" + damPrincipalID
	remaining, removed, err := wh.ManageAccountKeys(context.Background(), "project", expectedUserName, params.TTL, params.MaxKeyTTL, time.Now(), int64(params.ManagedKeysPerAccount))

	if err != nil {
		t.Errorf("manage keys encountered error: %v", err)
		// no point in trying other assertions
		return
	}
	if removed != 0 {
		t.Errorf("expected 0 keys to be removed but observed %d", removed)
	}
	if remaining != params.ManagedKeysPerAccount {
		t.Errorf("expected %d keys to be remaining but observed %d", params.ManagedKeysPerAccount, remaining)
	}
}

func TestAWS_ManageAccountKeys_AboveThreshold(t *testing.T) {
	awsAccount := "12345678"
	damPrincipalID := "dam-user-id"
	apiClient := NewMockAPIClient(awsAccount, damPrincipalID)
	wh, _ := NewWarehouse(context.Background(), apiClient)

	// AWS has 12-hour threshold for role access tokens
	params := NewMockBucketParams(13 * time.Hour)
	for i := 0; i < params.ManagedKeysPerAccount; i++ {
		_, err := wh.MintTokenWithTTL(context.Background(), params)
		if err != nil {
			t.Errorf("prerequisite failed: error minting token: %v", err)
			// no point in trying other assertions
			return
		}
	}

	keys := apiClient.AccessKeys
	if len(keys) != params.ManagedKeysPerAccount {
		t.Errorf("precondition failed: expected %d keys but only found %d", params.ManagedKeysPerAccount, len(keys))
		// no point in trying other assertions
		return
	}

	firstKey := keys[0]

	expectedUserName := "ic_abc123@" + damPrincipalID
	remaining, removed, err := wh.ManageAccountKeys(context.Background(), "project", expectedUserName, params.TTL, params.MaxKeyTTL, time.Now(), int64(params.ManagedKeysPerAccount-1))

	if err != nil {
		t.Errorf("manage keys encountered error: %v", err)
		// no point in trying other assertions
		return
	}
	if removed != 1 {
		t.Errorf("expected 1 keys to be removed but observed %d", removed)
	}
	if remaining != params.ManagedKeysPerAccount-1 {
		t.Errorf("expected %d keys to be remaining but observed %d", params.ManagedKeysPerAccount, remaining)
	}

	for _, key := range apiClient.AccessKeys {
		if key.AccessKeyId == firstKey.AccessKeyId {
			t.Errorf("expected first key to be removed")
			break
		}
	}
}

func TestAWS_ManageAccountKeys_Expired(t *testing.T) {
	awsAccount := "12345678"
	damPrincipalID := "dam-user-id"
	apiClient := NewMockAPIClient(awsAccount, damPrincipalID)
	wh, _ := NewWarehouse(context.Background(), apiClient)

	// AWS has 12-hour threshold for role access tokens
	params := NewMockBucketParams(13 * time.Hour)
	_, err := wh.MintTokenWithTTL(context.Background(), params)
	if err != nil {
		t.Errorf("prerequisite failed: error minting token: %v", err)
		// no point in trying other assertions
		return
	}

	keys := apiClient.AccessKeys
	if len(keys) != 1 {
		t.Errorf("precondition failed: expected 1 keys but only found %d", len(keys))
		// no point in trying other assertions
		return
	}

	firstKey := keys[0]
	now := time.Now()
	firstKey.CreateDate = aws.Time(now.Add(-1 * (params.MaxKeyTTL+time.Hour)))

	expectedUserName := "ic_abc123@" + damPrincipalID
	remaining, removed, err := wh.ManageAccountKeys(context.Background(), "project", expectedUserName, params.TTL, params.MaxKeyTTL, now, int64(params.ManagedKeysPerAccount-1))

	if err != nil {
		t.Errorf("manage keys encountered error: %v", err)
		// no point in trying other assertions
		return
	}
	if removed != 1 {
		t.Errorf("expected 1 keys to be removed but observed %d", removed)
	}
	if remaining != 0 {
		t.Errorf("expected 0 keys to be remaining but observed %d", remaining)
	}

	if len(apiClient.AccessKeys) != 0 {
		t.Errorf("expected key to be removed")
	}
}

func validateMintedRoleCredentials(t *testing.T, expectedAccount string, result *ResourceTokenResult, err error) {
	if err != nil {
		t.Errorf("expected minting a token but got error: %v", err)
		return
	}
	if result == nil {
		t.Error("expected non-nil result but result was nil")
		return
	}

	if result.Account != expectedAccount {
		t.Errorf("expected account [%s] but observed [%s]", expectedAccount, result.Account)
	}
	if !strings.HasSuffix(result.AccessKeyID, "-id") {
		t.Errorf("expected AccessKeyID to be mocked id value but was [%s]", result.AccessKeyID)
	}
	if !strings.HasSuffix(result.SecretAccessKey, "-key") {
		t.Errorf("expected SecretAccessKey to be mocked key value but was [%s]", result.SecretAccessKey)
	}
	if !strings.HasSuffix(result.SessionToken, "-session-token") {
		t.Errorf("expected SessionToken to be mocked session token value but was [%s]", result.SessionToken)
	}
}

func validateMintedAccessKey(t *testing.T, expectedAccount string, result *ResourceTokenResult, err error) {
	if err != nil {
		t.Errorf("expected minting a token but got error: %v", err)
		return
	}
	if result == nil {
		t.Error("expected non-nil result but result was nil")
		return
	}

	if result.Account != expectedAccount {
		t.Errorf("expected account [%s] but observed [%s]", expectedAccount, result.Account)
	}
	if !strings.HasSuffix(result.AccessKeyID, "-id") {
		t.Errorf("expected AccessKeyID to be mocked id value but was [%s]", result.AccessKeyID)
	}
	if !strings.HasSuffix(result.SecretAccessKey, "-key") {
		t.Errorf("expected SecretAccessKey to be mocked key value but was [%s]", result.SecretAccessKey)
	}
	if result.SessionToken != "" {
		t.Errorf("expected SessionToken to be empty for access key but was [%s]", result.SessionToken)
	}
}

func validateCreatedRolePolicy(t *testing.T, apiClient *MockAwsClient, expectedRoleName string, targetRoles []string) {
	if len(apiClient.Roles) != 1 {
		t.Errorf("expected a single role to be created but found %v", apiClient.Roles)
	} else {
		role := apiClient.Roles[0]
		if *role.RoleName != expectedRoleName {
			t.Errorf("expected created role name to be [%s] but was [%s]", expectedRoleName, *role.RoleName)
		}
	}

	if len(apiClient.RolePolicies) != 1 {
		t.Errorf("expected a single role policy to be created but found %v", apiClient.RolePolicies)
	} else {
		policy := apiClient.RolePolicies[0]
		if *policy.RoleName != expectedRoleName {
			t.Errorf("expected policy to be created for role [%s] but was created for role [%s]",
				expectedRoleName,
				*policy.RoleName)
		}
		for _, targetRole := range targetRoles {
			if !strings.Contains(*policy.PolicyDocument, targetRole) {
				t.Errorf("expected policy document to contain target role [%s] but this was the policy document:\n%s",
					targetRole,
					*policy.PolicyDocument)
			}
		}
	}
}

func validateCreatedUserPolicy(t *testing.T, apiClient *MockAwsClient, expectedUserName string, targetRoles []string) {
	if len(apiClient.Users) != 1 {
		t.Errorf("expected a single user to be created but found %v", apiClient.Users)
	} else {
		user := apiClient.Users[0]
		if *user.UserName != expectedUserName {
			t.Errorf("expected created user name to be [%s] but was [%s]", expectedUserName, *user.UserName)
		}
	}

	if len(apiClient.UserPolicies) != 1 {
		t.Errorf("expected a single user policy to be created but found %v", apiClient.UserPolicies)
	} else {
		policy := apiClient.UserPolicies[0]
		if *policy.UserName != expectedUserName {
			t.Errorf("expected policy to be created for user [%s] but was created for user [%s]",
				expectedUserName,
				*policy.UserName)
		}
		for _, targetUser := range targetRoles {
			if !strings.Contains(*policy.PolicyDocument, targetUser) {
				t.Errorf("expected policy document to contain target role [%s] but this was the policy document:\n%s",
					targetUser,
					*policy.PolicyDocument)
			}
		}
	}
}
