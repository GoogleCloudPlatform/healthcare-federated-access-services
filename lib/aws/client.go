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

// Package gcp abstracts interacting with certain aspects of Google Cloud
// Platform, such as creating service account keys and access tokens.
package aws

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
)

type SdkApiClient struct {
	session *session.Session
	iamSvc  *iam.IAM
	stsSvc  *sts.STS
}

func NewApiClient() (*SdkApiClient, error) {
	session, err := session.NewSession(&aws.Config{})
	if err != nil {
		return nil, fmt.Errorf("unable to create AWS root session: %v", err)
	}
	return &SdkApiClient{
		session: session,
		iamSvc:  iam.New(session),
		stsSvc:  sts.New(session),
	}, nil
}

func (sac *SdkApiClient) ListUsers(input *iam.ListUsersInput) (*iam.ListUsersOutput, error) {
	return sac.iamSvc.ListUsers(input)
}

func (sac *SdkApiClient) ListAccessKeys(input *iam.ListAccessKeysInput) (*iam.ListAccessKeysOutput, error) {
	return sac.iamSvc.ListAccessKeys(input)
}

func (sac *SdkApiClient) DeleteAccessKey(input *iam.DeleteAccessKeyInput) (*iam.DeleteAccessKeyOutput, error) {
	return sac.iamSvc.DeleteAccessKey(input)
}

func (sac *SdkApiClient) GetCallerIdentity(input *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
	return sac.stsSvc.GetCallerIdentity(input)
}

func (sac *SdkApiClient) AssumeRole(input *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
	return sac.stsSvc.AssumeRole(input)
}

func (sac *SdkApiClient) CreateAccessKey(input *iam.CreateAccessKeyInput) (*iam.CreateAccessKeyOutput, error) {
	return sac.iamSvc.CreateAccessKey(input)
}

func (sac *SdkApiClient) PutRolePolicy(input *iam.PutRolePolicyInput) (*iam.PutRolePolicyOutput, error) {
	return sac.iamSvc.PutRolePolicy(input)
}

func (sac *SdkApiClient) PutUserPolicy(input *iam.PutUserPolicyInput) (*iam.PutUserPolicyOutput, error) {
	return sac.iamSvc.PutUserPolicy(input)
}

func (sac *SdkApiClient) GetUser(input *iam.GetUserInput) (*iam.GetUserOutput, error) {
	return sac.iamSvc.GetUser(input)
}

func (sac *SdkApiClient) CreateUser(input *iam.CreateUserInput) (*iam.CreateUserOutput, error) {
	return sac.iamSvc.CreateUser(input)
}

func (sac *SdkApiClient) GetRole(input *iam.GetRoleInput) (*iam.GetRoleOutput, error) {
	return sac.iamSvc.GetRole(input)
}

func (sac *SdkApiClient) CreateRole(input *iam.CreateRoleInput) (*iam.CreateRoleOutput, error) {
	return sac.iamSvc.CreateRole(input)
}
