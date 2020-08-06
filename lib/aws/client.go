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
	"fmt"
	"math/rand"
	"time"

	"github.com/aws/aws-sdk-go/aws" /* copybara-comment */
	"github.com/aws/aws-sdk-go/aws/awserr" /* copybara-comment */
	"github.com/aws/aws-sdk-go/aws/session" /* copybara-comment */
	"github.com/aws/aws-sdk-go/service/iam" /* copybara-comment */
	"github.com/aws/aws-sdk-go/service/sts" /* copybara-comment */
)

type sdkAPIClient struct {
	session *session.Session
	iamSvc  *iam.IAM
	stsSvc  *sts.STS
}

// NewAPIClient creates a new APIClient that delegates to the AWS SDK using the default
// AWS credentials provider.
func NewAPIClient() (APIClient, error) {
	session, err := session.NewSession(&aws.Config{})
	if err != nil {
		return nil, fmt.Errorf("unable to create AWS root session: %v", err)
	}

	return &sdkAPIClient{
		session: session,
		iamSvc:  iam.New(session),
		stsSvc:  sts.New(session),
	}, nil
}

func (sac *sdkAPIClient) ListUsers(input *iam.ListUsersInput) (*iam.ListUsersOutput, error) {
	return sac.iamSvc.ListUsers(input)
}

func (sac *sdkAPIClient) ListAccessKeys(input *iam.ListAccessKeysInput) (*iam.ListAccessKeysOutput, error) {
	return sac.iamSvc.ListAccessKeys(input)
}

func (sac *sdkAPIClient) DeleteAccessKey(input *iam.DeleteAccessKeyInput) (*iam.DeleteAccessKeyOutput, error) {
	return sac.iamSvc.DeleteAccessKey(input)
}

func (sac *sdkAPIClient) GetCallerIdentity(input *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
	return sac.stsSvc.GetCallerIdentity(input)
}

func (sac *sdkAPIClient) AssumeRole(input *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
	return sac.stsSvc.AssumeRole(input)
}

func (sac *sdkAPIClient) CreateAccessKey(input *iam.CreateAccessKeyInput) (*iam.CreateAccessKeyOutput, error) {
	return sac.iamSvc.CreateAccessKey(input)
}

func (sac *sdkAPIClient) PutRolePolicy(input *iam.PutRolePolicyInput) (*iam.PutRolePolicyOutput, error) {
	return sac.iamSvc.PutRolePolicy(input)
}

func (sac *sdkAPIClient) PutUserPolicy(input *iam.PutUserPolicyInput) (*iam.PutUserPolicyOutput, error) {
	return sac.iamSvc.PutUserPolicy(input)
}

func (sac *sdkAPIClient) GetUser(input *iam.GetUserInput) (*iam.GetUserOutput, error) {
	return sac.iamSvc.GetUser(input)
}

func (sac *sdkAPIClient) CreateUser(input *iam.CreateUserInput) (*iam.CreateUserOutput, error) {
	return sac.iamSvc.CreateUser(input)
}

func (sac *sdkAPIClient) GetRole(input *iam.GetRoleInput) (*iam.GetRoleOutput, error) {
	return sac.iamSvc.GetRole(input)
}

func (sac *sdkAPIClient) CreateRole(input *iam.CreateRoleInput) (*iam.CreateRoleOutput, error) {
	return sac.iamSvc.CreateRole(input)
}

func (sac *sdkAPIClient) CreateLoginProfile(input *iam.CreateLoginProfileInput) (*iam.CreateLoginProfileOutput, error) {
	return sac.iamSvc.CreateLoginProfile(input)
}

func (sac *sdkAPIClient) UpdateLoginProfile(input *iam.UpdateLoginProfileInput) (*iam.UpdateLoginProfileOutput, error) {
	return sac.iamSvc.UpdateLoginProfile(input)
}

func (sac *sdkAPIClient) GetLoginProfile(input *iam.GetLoginProfileInput) (*iam.GetLoginProfileOutput, error) {
	return sac.iamSvc.GetLoginProfile(input)
}

func (sac *sdkAPIClient) DeleteLoginProfile(input *iam.DeleteLoginProfileInput) (*iam.DeleteLoginProfileOutput, error) {
	return sac.iamSvc.DeleteLoginProfile(input)
}

func (sac *sdkAPIClient) ListUserPolicies(input *iam.ListUserPoliciesInput) (*iam.ListUserPoliciesOutput, error) {
	return sac.iamSvc.ListUserPolicies(input)
}

func (sac *sdkAPIClient) DeleteUserPolicy(input *iam.DeleteUserPolicyInput) (*iam.DeleteUserPolicyOutput, error) {
	return sac.iamSvc.DeleteUserPolicy(input)
}

func (sac *sdkAPIClient) DeleteUser(input *iam.DeleteUserInput) (*iam.DeleteUserOutput, error) {
	return sac.iamSvc.DeleteUser(input)
}

// NewMockAPIClient provides an API client implementation suitable for unit tests.
func NewMockAPIClient(account string, userID string) *MockAwsClient {
	return &MockAwsClient{
		Account: account,
		UserID:  userID,
	}
}

type fullLoginProfile struct {
	loginProfile *iam.LoginProfile
	password     *string
}

// MockAwsClient for testing
type MockAwsClient struct {
	Account          string
	UserID           string
	Roles            []*iam.Role
	RolePolicies     []*iam.PutRolePolicyInput
	AssumedRoles     []*sts.AssumeRoleInput
	Users            []*iam.User
	UserPolicies     []*iam.PutUserPolicyInput
	AccessKeys       []*iam.AccessKey
	FullLoginProfile []*fullLoginProfile
}

// CreateLoginProfile ...
func (m *MockAwsClient) CreateLoginProfile(input *iam.CreateLoginProfileInput) (*iam.CreateLoginProfileOutput, error) {
	if _, err := m.GetLoginProfile(&iam.GetLoginProfileInput{UserName: input.UserName}); err == nil {
		return nil, awserr.New(iam.ErrCodeEntityAlreadyExistsException, "should not depend on this", nil)
	}

	fullLoginProfile := &fullLoginProfile{
		loginProfile: &iam.LoginProfile{
			CreateDate:            aws.Time(time.Now()),
			PasswordResetRequired: input.PasswordResetRequired,
			UserName:              input.UserName,
		},
		password: input.Password,
	}

	m.FullLoginProfile = append(m.FullLoginProfile, fullLoginProfile)

	return &iam.CreateLoginProfileOutput{
		LoginProfile: fullLoginProfile.loginProfile,
	}, nil
}

// DeleteLoginProfile ...
func (m *MockAwsClient) DeleteLoginProfile(input *iam.DeleteLoginProfileInput) (*iam.DeleteLoginProfileOutput, error) {
	for i, profile := range m.FullLoginProfile {
		if *profile.loginProfile.UserName == *input.UserName {
			newProfiles := make([]*fullLoginProfile, len(m.FullLoginProfile)-1)
			copy(newProfiles, m.FullLoginProfile[0:i])
			copy(newProfiles[i:], m.FullLoginProfile[i+1:])
			m.FullLoginProfile = newProfiles
			return &iam.DeleteLoginProfileOutput{}, nil
		}
	}

	return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "should not depend on this", nil)
}

// UpdateLoginProfile ...
func (m *MockAwsClient) UpdateLoginProfile(input *iam.UpdateLoginProfileInput) (*iam.UpdateLoginProfileOutput, error) {
	for _, flp := range m.FullLoginProfile {
		if *flp.loginProfile.UserName == *input.UserName {
			flp.password = input.Password
			flp.loginProfile.PasswordResetRequired = input.PasswordResetRequired
			return &iam.UpdateLoginProfileOutput{}, nil
		}
	}

	return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "shouldn't rely on this", nil)
}

// GetLoginProfile ...
func (m *MockAwsClient) GetLoginProfile(input *iam.GetLoginProfileInput) (*iam.GetLoginProfileOutput, error) {
	for _, flp := range m.FullLoginProfile {
		if *flp.loginProfile.UserName == *input.UserName {
			return &iam.GetLoginProfileOutput{
				LoginProfile: flp.loginProfile,
			}, nil
		}
	}

	return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "shouldn't rely on this", nil)
}

// ListUsers ...
func (m *MockAwsClient) ListUsers(_ *iam.ListUsersInput) (*iam.ListUsersOutput, error) {
	return &iam.ListUsersOutput{
		IsTruncated: aws.Bool(false),
		Marker:      nil,
		Users:       []*iam.User{},
	}, nil
}

// ListAccessKeys ...
func (m *MockAwsClient) ListAccessKeys(input *iam.ListAccessKeysInput) (*iam.ListAccessKeysOutput, error) {
	if _, err := m.GetUser(&iam.GetUserInput{UserName: input.UserName}); err != nil {
		return nil, err
	}

	var list []*iam.AccessKeyMetadata
	for _, key := range m.AccessKeys {
		if *key.UserName == *input.UserName {
			km := &iam.AccessKeyMetadata{
				AccessKeyId: key.AccessKeyId,
				CreateDate:  key.CreateDate,
				Status:      key.Status,
				UserName:    key.UserName,
			}
			list = append(list, km)
		}
	}

	return &iam.ListAccessKeysOutput{
		AccessKeyMetadata: list,
		IsTruncated:       aws.Bool(false),
		Marker:            nil,
	}, nil
}

// DeleteAccessKey ...
func (m *MockAwsClient) DeleteAccessKey(input *iam.DeleteAccessKeyInput) (*iam.DeleteAccessKeyOutput, error) {
	for i, key := range m.AccessKeys {
		if key.AccessKeyId == input.AccessKeyId {
			newKeys := make([]*iam.AccessKey, len(m.AccessKeys)-1)
			copy(newKeys, m.AccessKeys[0:i])
			copy(newKeys[i:], m.AccessKeys[i+1:])
			m.AccessKeys = newKeys
			return &iam.DeleteAccessKeyOutput{}, nil
		}
	}

	return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "shouldn't rely on this message", nil)
}

// GetCallerIdentity ...
func (m *MockAwsClient) GetCallerIdentity(_ *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
	return &sts.GetCallerIdentityOutput{
		Account: &m.Account,
		Arn:     aws.String(fmt.Sprintf("arn:aws:iam::%s:user/%s", m.Account, m.UserID)),
		UserId:  &m.UserID,
	}, nil
}

// AssumeRole ...
func (m *MockAwsClient) AssumeRole(input *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
	for _, role := range m.Roles {
		if *input.RoleArn == *role.Arn {
			m.AssumedRoles = append(m.AssumedRoles, input)
			duration := time.Duration(*input.DurationSeconds) * time.Second
			cred := fmt.Sprintf("%s-%d", time.Now().String(), rand.Int())
			return &sts.AssumeRoleOutput{
				AssumedRoleUser: &sts.AssumedRoleUser{
					Arn:           input.RoleArn,
					AssumedRoleId: role.RoleId,
				},
				Credentials: &sts.Credentials{
					AccessKeyId:     aws.String(cred + "-id"),
					Expiration:      aws.Time(time.Now().Add(duration)),
					SecretAccessKey: aws.String(cred + "-key"),
					SessionToken:    aws.String(cred + "-session-token"),
				},
				PackedPolicySize: aws.Int64(0),
			}, nil
		}
	}

	return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "shouldn't depend on this message", nil)
}

// CreateAccessKey ...
func (m *MockAwsClient) CreateAccessKey(input *iam.CreateAccessKeyInput) (*iam.CreateAccessKeyOutput, error) {
	if _, err := m.GetUser(&iam.GetUserInput{UserName: input.UserName}); err != nil {
		return nil, err
	}

	cred := fmt.Sprintf("%s-%d", time.Now().String(), rand.Int())
	key := &iam.AccessKey{
		AccessKeyId:     aws.String(cred + "-id"),
		CreateDate:      aws.Time(time.Now()),
		SecretAccessKey: aws.String(cred + "-key"),
		Status:          aws.String("Active"),
		UserName:        input.UserName,
	}
	m.AccessKeys = append(m.AccessKeys, key)

	return &iam.CreateAccessKeyOutput{
		AccessKey: key,
	}, nil
}

// PutRolePolicy ...
func (m *MockAwsClient) PutRolePolicy(input *iam.PutRolePolicyInput) (*iam.PutRolePolicyOutput, error) {
	if _, err := m.GetRole(&iam.GetRoleInput{RoleName: input.RoleName}); err != nil {
		return nil, err
	}
	m.RolePolicies = append(m.RolePolicies, input)
	return &iam.PutRolePolicyOutput{}, nil
}

// PutUserPolicy ...
func (m *MockAwsClient) PutUserPolicy(input *iam.PutUserPolicyInput) (*iam.PutUserPolicyOutput, error) {
	if _, err := m.GetUser(&iam.GetUserInput{UserName: input.UserName}); err != nil {
		return nil, err
	}
	m.UserPolicies = append(m.UserPolicies, input)
	return &iam.PutUserPolicyOutput{}, nil
}

// ListUserPolicies ...
func (m *MockAwsClient) ListUserPolicies(input *iam.ListUserPoliciesInput) (*iam.ListUserPoliciesOutput, error) {
	if _, err := m.GetUser(&iam.GetUserInput{UserName: input.UserName}); err != nil {
		return nil, err
	}
	policyNames := make([]*string, 0)
	for _, policyInput := range m.UserPolicies {
		if *policyInput.UserName == *input.UserName {
			policyNames = append(policyNames, policyInput.PolicyName)
		}
	}

	return &iam.ListUserPoliciesOutput{
		IsTruncated: aws.Bool(false),
		Marker:      nil,
		PolicyNames: policyNames,
	}, nil
}

// DeleteUserPolicy ...
func (m *MockAwsClient) DeleteUserPolicy(input *iam.DeleteUserPolicyInput) (*iam.DeleteUserPolicyOutput, error) {
	if _, err := m.GetUser(&iam.GetUserInput{UserName: input.UserName}); err != nil {
		return nil, err
	}

	newPolicies := make([]*iam.PutUserPolicyInput, 0)
	for _, policyInput := range m.UserPolicies {
		if *policyInput.UserName != *input.UserName {
			newPolicies = append(newPolicies, policyInput)
		}
	}
	m.UserPolicies = newPolicies

	return &iam.DeleteUserPolicyOutput{}, nil
}

// GetUser ...
func (m *MockAwsClient) GetUser(input *iam.GetUserInput) (*iam.GetUserOutput, error) {
	for _, user := range m.Users {
		if *input.UserName == *user.UserName {
			return &iam.GetUserOutput{
				User: user,
			}, nil
		}
	}

	return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "shouldn't depend on this message", nil)
}

// CreateUser ...
func (m *MockAwsClient) CreateUser(input *iam.CreateUserInput) (*iam.CreateUserOutput, error) {
	if user, _ := m.GetUser(&iam.GetUserInput{UserName: input.UserName}); user != nil {
		return nil, awserr.New(iam.ErrCodeEntityAlreadyExistsException, "shouldn't depend on this message", nil)
	}

	var nameWithPath string
	if input.Path != nil {
		nameWithPath = *input.UserName
	} else {
		nameWithPath = (*input.Path)[1:] + *input.UserName
	}
	user := &iam.User{
		Arn:                 aws.String(fmt.Sprintf("arn:aws:iam::%s:user/%s", m.Account, nameWithPath)),
		CreateDate:          aws.Time(time.Now()),
		PasswordLastUsed:    nil,
		Path:                input.Path,
		PermissionsBoundary: nil,
		Tags:                input.Tags,
		UserId:              aws.String(nameWithPath),
		UserName:            input.UserName,
	}
	m.Users = append(m.Users, user)

	return &iam.CreateUserOutput{
		User: user,
	}, nil
}

// DeleteUser ...
func (m *MockAwsClient) DeleteUser(input *iam.DeleteUserInput) (*iam.DeleteUserOutput, error) {
	for i, user := range m.Users {
		if *input.UserName == *user.UserName {
			newUsers := make([]*iam.User, len(m.Users)-1)
			copy(newUsers, m.Users[0:i])
			copy(newUsers[i:], m.Users[i+1:])
			m.Users = newUsers
			return &iam.DeleteUserOutput{}, nil
		}
	}

	return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "should not depend on this", nil)
}

// GetRole ...
func (m *MockAwsClient) GetRole(input *iam.GetRoleInput) (*iam.GetRoleOutput, error) {
	for _, role := range m.Roles {
		if *role.RoleName == *input.RoleName {
			return &iam.GetRoleOutput{
				Role: role,
			}, nil
		}
	}

	return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "shouldn't depend on this message", nil)
}

// CreateRole ...
func (m *MockAwsClient) CreateRole(input *iam.CreateRoleInput) (*iam.CreateRoleOutput, error) {
	if role, _ := m.GetRole(&iam.GetRoleInput{RoleName: input.RoleName}); role != nil {
		return nil, awserr.New(iam.ErrCodeEntityAlreadyExistsException, "shouldn't depend on this message", nil)
	}

	var nameWithPath string
	if input.Path == nil {
		nameWithPath = *input.RoleName
	} else {
		nameWithPath = (*input.Path)[1:] + *input.RoleName
	}

	role := &iam.Role{
		Arn:                      aws.String(fmt.Sprintf("arn:aws:iam::%s:role/%s", m.Account, nameWithPath)),
		AssumeRolePolicyDocument: input.AssumeRolePolicyDocument,
		Description:              input.Description,
		MaxSessionDuration:       input.MaxSessionDuration,
		Path:                     input.Path,
		PermissionsBoundary:      nil,
		RoleId:                   aws.String(nameWithPath),
		RoleName:                 input.RoleName,
		Tags:                     input.Tags,
	}
	m.Roles = append(m.Roles, role)

	return &iam.CreateRoleOutput{
		Role: role,
	}, nil
}
