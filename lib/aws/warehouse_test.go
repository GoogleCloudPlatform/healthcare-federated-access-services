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

// Package aws abstracts interacting with certain aspects of AWS,
// such as creating IAM roles and user, account keys, and access tokens.
package aws

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws" /* copybara-comment */

	v1 "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1"
)

// end Mock AWS Client

func NewMockBucketParams(ttl time.Duration, paths *string) *ResourceParams {
	var vars = map[string]string{"bucket": "test-bucket-name"}
	if paths != nil {
		vars["paths"] = *paths
	}
	return &ResourceParams{
		UserID:                "ic_abc123|fake-ic",
		TTL:                   ttl,
		MaxKeyTTL:             (24 * 30) * time.Hour,
		ManagedKeysPerAccount: 2,
		Vars:                  vars,
		TargetRoles:           []string{"s3:GetObject", "s3:GetBucketLocation"},
		TargetScopes:          []string{},
		DamResourceID:         "res-id",
		DamViewID:             "view-id",
		DamRoleID:             "role-id",
		ServiceTemplate:       &v1.ServiceTemplate{ServiceName: "s3bucket"},
	}
}

func NewMockRedshiftParams(ttl time.Duration) *ResourceParams {
	vars := map[string]string{
		"cluster": "arn:aws:redshift:us-east-1:12345678:cluster:test-cluster",
		"group": "arn:aws:redshift:us-east-1:12345678:dbgroup:test-cluster/admin",
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
		ServiceTemplate:       &v1.ServiceTemplate{ServiceName: "redshift"},
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
	params := NewMockBucketParams(time.Hour, nil)

	result, err := wh.MintTokenWithTTL(context.Background(), params)

	expectedRoleName := fmt.Sprintf("%s,%s,%s@%s", params.DamResourceID, params.DamViewID, params.DamRoleID, damPrincipalID)
	expectedRoleArn := fmt.Sprintf("arn:aws:iam::%s:role/ddap/%s", awsAccount, expectedRoleName)
	validateMintedRoleCredentials(t, awsAccount, expectedRoleArn, result, err)
	validateCreatedRolePolicy(t, apiClient, expectedRoleName, params.TargetRoles)
}

func TestAWS_MintTokenWithShortLivedTTL_BucketWithUndefinedPaths(t *testing.T) {
	damPrincipalID := "dam-user-id"
	awsAccount := "12345678"
	apiClient := NewMockAPIClient(awsAccount, damPrincipalID)
	wh, _ := NewWarehouse(context.Background(), apiClient)
	params := NewMockBucketParams(time.Hour, nil)

	result, err := wh.MintTokenWithTTL(context.Background(), params)

	expectedRoleName := fmt.Sprintf("%s,%s,%s@%s", params.DamResourceID, params.DamViewID, params.DamRoleID, damPrincipalID)
	expectedRoleArn := fmt.Sprintf("arn:aws:iam::%s:role/ddap/%s", awsAccount, expectedRoleName)
	validateMintedRoleCredentials(t, awsAccount, expectedRoleArn, result, err)
	validateCreatedRolePolicy(t, apiClient, expectedRoleName, params.TargetRoles)

	policy := apiClient.RolePolicies[0]
	policyDoc := policy.PolicyDocument
	expectedResourcePaths := []string{
		fmt.Sprintf("arn:aws:s3:::%s/*", params.Vars["bucket"]),
		fmt.Sprintf("arn:aws:s3:::%s", params.Vars["bucket"]),
	}
	validatePolicyResourceARNs(t, expectedResourcePaths, policyDoc)
}

func TestAWS_MintTokenWithShortLivedTTL_BucketWithDefinedPaths(t *testing.T) {
	damPrincipalID := "dam-user-id"
	awsAccount := "12345678"
	apiClient := NewMockAPIClient(awsAccount, damPrincipalID)
	wh, _ := NewWarehouse(context.Background(), apiClient)
	path1 := "/path/to/object1.txt"
	path2 := "/path/to/objects/*"
	paths := fmt.Sprintf("%s;%s", path1, path2)
	params := NewMockBucketParams(time.Hour, &paths)

	result, err := wh.MintTokenWithTTL(context.Background(), params)

	expectedRoleName := fmt.Sprintf("%s,%s,%s@%s", params.DamResourceID, params.DamViewID, params.DamRoleID, damPrincipalID)
	expectedRoleArn := fmt.Sprintf("arn:aws:iam::%s:role/ddap/%s", awsAccount, expectedRoleName)
	validateMintedRoleCredentials(t, awsAccount, expectedRoleArn, result, err)
	validateCreatedRolePolicy(t, apiClient, expectedRoleName, params.TargetRoles)

	policy := apiClient.RolePolicies[0]
	policyDoc := policy.PolicyDocument
	expectedResourcePaths := []string{
		fmt.Sprintf("arn:aws:s3:::%s%s", params.Vars["bucket"], path1),
		fmt.Sprintf("arn:aws:s3:::%s%s", params.Vars["bucket"], path2),
	}
	validatePolicyResourceARNs(t, expectedResourcePaths, policyDoc)
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
	validateMintedRoleCredentials(t, awsAccount, expectedRoleArn, result, err)
	validateCreatedRolePolicy(t, apiClient, expectedRoleName, params.TargetRoles)

	dbUserArn := "arn:aws:redshift:us-east-1:12345678:dbuser:test-cluster/ic_abc123@dam-user-id"
	wildcardUserArn := "arn:aws:redshift:us-east-1:12345678:dbuser:test-cluster/*"
	policyDoc := *apiClient.RolePolicies[0].PolicyDocument
	if strings.Contains(policyDoc, dbUserArn) {
		t.Errorf("policy doc for role policy shouldn't reference specific db user: %s", policyDoc)
	}
	if !strings.Contains(policyDoc, wildcardUserArn) {
		t.Errorf("policy doc for role policy should reference wildcard db user: %s", policyDoc)
	}

	if len(apiClient.AssumedRoles) != 1 {
		t.Fatalf("expected a single role to be assumed but found %v", apiClient.AssumedRoles)
	}

	assumedRoleInput := apiClient.AssumedRoles[0]
	validatePolicyDoc(t, params.TargetRoles, assumedRoleInput.Policy)
	if strings.Contains(*assumedRoleInput.Policy, wildcardUserArn) {
		t.Errorf("policy doc for role policy shouldn't reference wildcard db user: %s", *assumedRoleInput.Policy)
	}
	if !strings.Contains(*assumedRoleInput.Policy, dbUserArn) {
		t.Errorf("policy doc for role policy should reference specific db user: %s", *assumedRoleInput.Policy)
	}
}

func TestAWS_MintTokenWithLongLivedTTL_Bucket(t *testing.T) {
	awsAccount := "12345678"
	damPrincipalID := "dam-user-id"
	apiClient := NewMockAPIClient(awsAccount, damPrincipalID)
	wh, _ := NewWarehouse(context.Background(), apiClient)
	// AWS has 12-hour threshold for role access tokens
	params := NewMockBucketParams(13 * time.Hour, nil)

	result, err := wh.MintTokenWithTTL(context.Background(), params)

	expectedUserName := "ic_abc123@" + damPrincipalID
	expectedUserArn := fmt.Sprintf("arn:aws:iam::%s:user/%s", awsAccount, expectedUserName)
	validateMintedAccessKey(t, awsAccount, expectedUserArn, result, err)
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
	validateMintedAccessKey(t, awsAccount, expectedUserArn, result, err)
	validateCreatedUserPolicy(t, apiClient, expectedUserName, params.TargetRoles)
}

func TestAWS_MintTokenWithHumanAccess_Bucket(t *testing.T) {
	awsAccount := "12345678"
	damPrincipalID := "dam-user-id"
	apiClient := NewMockAPIClient(awsAccount, damPrincipalID)
	wh, _ := NewWarehouse(context.Background(), apiClient)
	params := NewMockBucketParams(1 * time.Hour, nil)
	params.DamInterfaceID = HumanInterfacePrefix + "s3"

	result, err := wh.MintTokenWithTTL(context.Background(), params)

	expectedUserName := "ic_abc123@" + damPrincipalID
	expectedUserArn := fmt.Sprintf("arn:aws:iam::%s:user/%s", awsAccount, expectedUserName)
	validateMintedUsernamePassword(t, awsAccount, expectedUserArn, expectedUserName, result, err)
	validateCreatedUserPolicy(t, apiClient, expectedUserName, params.TargetRoles)
}

func TestAWS_MintTokenWithHumanAccessConsecutively_Bucket(t *testing.T) {
	awsAccount := "12345678"
	damPrincipalID := "dam-user-id"
	apiClient := NewMockAPIClient(awsAccount, damPrincipalID)
	wh, _ := NewWarehouse(context.Background(), apiClient)
	params := NewMockBucketParams(1 * time.Hour, nil)
	params.DamInterfaceID = HumanInterfacePrefix + "s3"

	expectedUserName := "ic_abc123@" + damPrincipalID
	expectedUserArn := fmt.Sprintf("arn:aws:iam::%s:user/%s", awsAccount, expectedUserName)

	// First time
	result1, err := wh.MintTokenWithTTL(context.Background(), params)
	validateMintedUsernamePassword(t, awsAccount, expectedUserArn, expectedUserName, result1, err)
	validateCreatedUserPolicy(t, apiClient, expectedUserName, params.TargetRoles)

	// Second time
	result2, err := wh.MintTokenWithTTL(context.Background(), params)
	validateMintedUsernamePassword(t, awsAccount, expectedUserArn, expectedUserName, result2, err)
}

func TestAWS_ManageAccountKeys_BelowMax(t *testing.T) {
	awsAccount := "12345678"
	damPrincipalID := "dam-user-id"
	apiClient := NewMockAPIClient(awsAccount, damPrincipalID)
	wh, _ := NewWarehouse(context.Background(), apiClient)

	// AWS has 12-hour threshold for role access tokens
	params := NewMockBucketParams(13 * time.Hour, nil)
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
	params := NewMockBucketParams(13 * time.Hour, nil)
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
	params := NewMockBucketParams(13 * time.Hour, nil)
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

func validateMintedRoleCredentials(t *testing.T, expectedAccount, expectedPrincipal string, result *ResourceTokenResult, err error) {
	t.Helper()

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
	if result.PrincipalARN != expectedPrincipal {
		t.Errorf("expected principal [%s] but observed [%s]", expectedPrincipal, result.PrincipalARN)
	}
	if result.AccessKeyID == nil {
		t.Errorf("expected AccessKeyID to be mocked id value but was nil")
	} else if !strings.HasSuffix(*result.AccessKeyID, "-id") {
		t.Errorf("expected AccessKeyID to be mocked id value but was [%s]", *result.AccessKeyID)
	}
	if result.SecretAccessKey == nil {
		t.Errorf("expected SecretAccessKey to be mocked key value but was nil")
	} else if !strings.HasSuffix(*result.SecretAccessKey, "-key") {
		t.Errorf("expected SecretAccessKey to be mocked key value but was [%s]", *result.SecretAccessKey)
	}
	if result.SessionToken == nil {
		t.Errorf("expected SessionToken to be mocked key value but was nil")
	} else if !strings.HasSuffix(*result.SessionToken, "-session-token") {
		t.Errorf("expected SessionToken to be mocked session token value but was [%s]", *result.SessionToken)
	}
}

func validateMintedAccessKey(t *testing.T, expectedAccount, expectedPrincipal string, result *ResourceTokenResult, err error) {
	t.Helper()

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
	if result.PrincipalARN != expectedPrincipal {
		t.Errorf("expected principal [%s] but observed [%s]", expectedPrincipal, result.PrincipalARN)
	}
	if result.AccessKeyID == nil {
		t.Errorf("expected AccessKeyID to be mocked id value but was nil")
	} else if !strings.HasSuffix(*result.AccessKeyID, "-id") {
		t.Errorf("expected AccessKeyID to be mocked id value but was [%s]", *result.AccessKeyID)
	}
	if result.SecretAccessKey == nil {
		t.Errorf("expected SecretAccessKey to be mocked key value but was nil")
	} else if !strings.HasSuffix(*result.SecretAccessKey, "-key") {
		t.Errorf("expected SecretAccessKey to be mocked key value but was [%s]", *result.SecretAccessKey)
	}
	if result.SessionToken != nil {
		t.Errorf("expected SessionToken to be nil for access key but was [%s]", *result.SessionToken)
	}
}

func validateMintedUsernamePassword(t *testing.T, expectedAccount, expectedPrincipalARN, expectedUserName string, result *ResourceTokenResult, err error) {
	t.Helper()

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
	if result.PrincipalARN != expectedPrincipalARN {
		t.Errorf("expected principal [%s] but observed [%s]", expectedPrincipalARN, result.PrincipalARN)
	}
	if result.UserName == nil {
		t.Errorf("expected UserName to be mocked id value but was nil")
	} else if *result.UserName != expectedUserName {
		t.Errorf("expected UserName to be mocked id value but was [%s]", *result.UserName)
	}
	if result.Password == nil || *result.Password == "" {
		t.Errorf("expected Password to be mocked id value but was nil or empty")
	}
}

func validateCreatedRolePolicy(t *testing.T, apiClient *MockAwsClient, expectedRoleName string, targetRoles []string) {
	t.Helper()

	if len(apiClient.Roles) != 1 {
		t.Fatalf("expected a single role to be created but found %v", apiClient.Roles)
	} else {
		role := apiClient.Roles[0]
		if *role.RoleName != expectedRoleName {
			t.Errorf("expected created role name to be [%s] but was [%s]", expectedRoleName, *role.RoleName)
		}
	}

	if len(apiClient.RolePolicies) != 1 {
		t.Fatalf("expected a single role policy to be created but found %v", apiClient.RolePolicies)
	} else {
		policy := apiClient.RolePolicies[0]
		if *policy.RoleName != expectedRoleName {
			t.Fatalf("expected policy to be created for role [%s] but was created for role [%s]",
				expectedRoleName,
				*policy.RoleName)
		}
		policyDoc := policy.PolicyDocument
		validatePolicyDoc(t, targetRoles, policyDoc)
	}
}

func validatePolicyDoc(t *testing.T, targetRoles []string, policyDoc *string) {
	t.Helper()

	if policyDoc == nil {
		t.Fatalf("expected a policy doc but none found")
	}

	for _, targetRole := range targetRoles {
		if !strings.Contains(*policyDoc, targetRole) {
			t.Errorf("expected policy document to contain target role [%s] but this was the policy document:\n%s",
				targetRole,
				*policyDoc)
		}
	}
}

func validatePolicyResourceARNs(t *testing.T, expectedResourceARNs []string, policyDoc *string) {
	t.Helper()

	if policyDoc == nil {
		t.Errorf("expected a session policy but none found")
		return
	}

	for _, arn := range expectedResourceARNs {
		if !strings.Contains(*policyDoc, arn) {
			t.Errorf("expected policy document to contain resource with ARN [%s] but this was the policy document:\n%s",
				arn,
				*policyDoc)
		}
	}
}

func validateCreatedUserPolicy(t *testing.T, apiClient *MockAwsClient, expectedUserName string, targetRoles []string) {
	t.Helper()

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
