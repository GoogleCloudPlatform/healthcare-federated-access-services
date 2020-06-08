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

// Package aws abstracts interacting with certain aspects of AWS,
// such as creating IAM roles and user, account keys, and access tokens.
package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	v1 "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/cenkalti/backoff"
)

const (
	// TemporaryCredMaxTTL is the maximum TTL for an AWS access token.
	TemporaryCredMaxTTL = 12 * time.Hour
	// S3ItemFormat is the canonical item format identifier for S3 buckets.
	S3ItemFormat        = "s3bucket"
	// RedshiftItemFormat is the canonical item format identifier for Redshift clusters.
	RedshiftItemFormat  = "redshift"
)

type principalType int
const (
	userType principalType = iota
	roleType
)

type resourceType int
const (
	otherRType resourceType = iota
	bucketType
)

const (
	backoffInitialInterval     = 1 * time.Second
	backoffRandomizationFactor = 0.5
	backoffMultiplier          = 1.5
	backoffMaxInterval         = 3 * time.Second
	backoffMaxElapsedTime      = 10 * time.Second
)

var (
	exponentialBackoff = &backoff.ExponentialBackOff{
		InitialInterval:     backoffInitialInterval,
		RandomizationFactor: backoffRandomizationFactor,
		Multiplier:          backoffMultiplier,
		MaxInterval:         backoffMaxInterval,
		MaxElapsedTime:      backoffMaxElapsedTime,
		Clock:               backoff.SystemClock,
	}
)

// APIClient is a wrapper around the AWS SDK that can be mocked for unit testing.
type APIClient interface {
	ListUsers(input *iam.ListUsersInput) (*iam.ListUsersOutput, error)
	ListAccessKeys(input *iam.ListAccessKeysInput) (*iam.ListAccessKeysOutput, error)
	DeleteAccessKey(input *iam.DeleteAccessKeyInput) (*iam.DeleteAccessKeyOutput, error)
	GetCallerIdentity(input *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error)
	AssumeRole(input *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error)
	CreateAccessKey(input *iam.CreateAccessKeyInput) (*iam.CreateAccessKeyOutput, error)
	PutRolePolicy(input *iam.PutRolePolicyInput) (*iam.PutRolePolicyOutput, error)
	PutUserPolicy(input *iam.PutUserPolicyInput) (*iam.PutUserPolicyOutput, error)
	GetUser(input *iam.GetUserInput) (*iam.GetUserOutput, error)
	CreateUser(input *iam.CreateUserInput) (*iam.CreateUserOutput, error)
	GetRole(input *iam.GetRoleInput) (*iam.GetRoleOutput, error)
	CreateRole(input *iam.CreateRoleInput) (*iam.CreateRoleOutput, error)
}

// ResourceTokenResult is returned from MintTokenWithTTL for aws adapter.
type ResourceTokenResult struct {
	Account         string
	Format          string
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// AccountWarehouse is used to create AWS IAM Users and temporary credentials
type AccountWarehouse struct {
	account string
	svcUserARN string
	apiClient  APIClient
}

// NewWarehouse creates a new AccountWarehouse using the provided client
// and options.
func NewWarehouse(_ context.Context, awsClient APIClient) (*AccountWarehouse, error) {
	wh := &AccountWarehouse{
		apiClient: awsClient,
	}
	gcio, err := awsClient.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, err
	}
	wh.svcUserARN = *gcio.Arn
	wh.account, err = extractAccount(wh.svcUserARN)
	if err != nil {
		return nil, err
	}

	return wh, nil
}

// GetAwsAccount returns the AWS account used by this AccountWarehouse for creating IAM
// users, roles, and policies.
func (wh *AccountWarehouse) GetAwsAccount() string {
	return wh.account
}

// ResourceParams contains all the arguments necessary to call MintTokenWithTTL on an
// AWS AccountWarehouse.
type ResourceParams struct {
	UserID                string
	TTL                   time.Duration
	MaxKeyTTL             time.Duration
	ManagedKeysPerAccount int
	Vars                  map[string]string
	TargetRoles           []string
	TargetScopes          []string
	DamResourceID         string
	DamViewID             string
	DamRoleID             string
	ServiceTemplate       *v1.ServiceTemplate
}

type resourceSpec struct {
	rType resourceType
	arn   string
	id    string
}

type principalSpec struct {
	pType principalType
	// Used for roles that must be assumed
	damPrincipalARN string
	account         string
	params          *ResourceParams
}

type policySpec struct {
	principal *principalSpec
	rSpecs    []*resourceSpec
	params    *ResourceParams
}

func (spec *policySpec) getID() string {
	return spec.principal.getDamResourceViewRoleID()
}

func (spec *principalSpec) getID() string {
	switch spec.pType {
	case userType:
		return convertDamUserIDtoAwsName(spec.params.UserID, spec.damPrincipalARN)
	case roleType:
		return spec.getDamResourceViewRoleID()
	default:
		panic(fmt.Sprintf("cannot get ID for princpal type [%v]", spec.pType))
	}
}

func (spec *principalSpec) getDamResourceViewRoleID() string {
	return fmt.Sprintf("%s,%s,%s@%s", spec.params.DamResourceID, spec.params.DamViewID, spec.params.DamRoleID, extractUserName(spec.damPrincipalARN))
}

func (spec *principalSpec) getARN() string {
	switch spec.pType {
	case userType:
		return fmt.Sprintf("arn:aws:iam::%s:user/%s", spec.account, spec.getID())
	case roleType:
		return fmt.Sprintf("arn:aws:iam::%s:role/%s", spec.account, spec.getID())
	default:
		panic(fmt.Sprintf("cannot get ID for princpal type [%v]", spec.pType))
	}
}

func calculateDBuserARN(clusterARN string, userName string) (string, error) {
	parts := strings.Split(clusterARN, ":")
	if len(parts) < 7 {
		return "", fmt.Errorf("argument is not a proper cluster ARN: %s", clusterARN)
	}

	return fmt.Sprintf( "%s:%s:%s:%s:%s:dbuser:%s/%s", parts[0], parts[1], parts[2], parts[3], parts[4], parts[6], userName), nil
}

func extractAccount(arn string) (string, error) {
	parts := strings.Split(arn, ":")
	if len(parts) < 5 {
		return "", fmt.Errorf("argument is not a proper ARN: %s", arn)
	}

	return parts[4], nil
}

func extractClusterName(arn string) (string, error) {
	parts := strings.Split(arn, ":")
	if len(parts) < 7 {
		return "", fmt.Errorf("argument is not a proper ARN: %s", arn)
	}

	return parts[6], nil
}

func extractDBGroupName(arn string) (string, error) {
	arnParts := strings.Split(arn, ":")
	if len(arnParts) < 7 {
		return "", fmt.Errorf("argument is not a proper ARN: %s", arn)
	}
	pathParts := strings.Split(arnParts[6], "/")

	return pathParts[len(pathParts)-1], nil
}

// MintTokenWithTTL returns an AccountKey or an AccessToken depending on the TTL requested.
func (wh *AccountWarehouse) MintTokenWithTTL(ctx context.Context, params *ResourceParams) (*ResourceTokenResult, error) {
	if params.TTL > params.MaxKeyTTL {
		return nil, fmt.Errorf("given ttl [%s] is greater than max ttl [%s]", params.TTL, params.MaxKeyTTL)
	}

	princSpec := wh.determinePrincipalSpec(params)

	rSpecs, err := wh.determineResourceSpecs(params)
	if err != nil {
		return nil, err
	}
	polSpec := &policySpec{
		principal: princSpec,
		rSpecs:    rSpecs,
		params:    params,
	}

	principalARN, err := wh.ensurePrincipal(princSpec)
	if err != nil {
		return nil, err
	}
	err = wh.ensurePolicy(polSpec)
	if err != nil {
		return nil, err
	}

	return wh.ensureTokenResult(ctx, principalARN, princSpec)
}

func (wh *AccountWarehouse) determineResourceSpecs(params *ResourceParams) ([]*resourceSpec, error) {
	switch params.ServiceTemplate.ServiceName {
	case S3ItemFormat:
		bucket, ok := params.Vars["bucket"]
		if !ok {
			return nil, fmt.Errorf("no bucket specified")
		}
		return []*resourceSpec{
			{
				id:    bucket,
				arn:   fmt.Sprintf("arn:aws:s3:::%s/*", bucket),
				rType: bucketType,
			},
			{
				id:    bucket,
				arn:   fmt.Sprintf("arn:aws:s3:::%s", bucket),
				rType: bucketType,
			},
		}, nil
	case RedshiftItemFormat:
		clusterARN, ok := params.Vars["cluster"]
		if !ok {
			return nil, fmt.Errorf("no cluster specified")
		}
		clusterName, err := extractClusterName(clusterARN)
		if err != nil {
			return nil, err
		}
		clusterSpec := &resourceSpec{
			rType: otherRType,
			arn:   clusterARN,
			id:    clusterName,
		}
		dbUser := convertDamUserIDtoAwsName(params.UserID, wh.svcUserARN)
		dbUserARN, err := calculateDBuserARN(clusterARN, dbUser)
		if err != nil {
			return nil, err
		}
		userSpec := &resourceSpec{
			rType: otherRType,
			arn:   dbUserARN,
			id:    dbUser,
		}
		group, ok := params.Vars["group"]
		if ok {
			dbGroupName, err := extractDBGroupName(group)
			if err != nil {
				return nil, err
			}
			return []*resourceSpec{
				clusterSpec,
				userSpec,
				{
					rType: otherRType,
					arn:   group,
					id:    dbGroupName,
				},
			}, nil
		}
		return []*resourceSpec{clusterSpec, userSpec}, nil

	default:
		return nil, fmt.Errorf("unrecognized item format [%s] for AWS target adapter", params.ServiceTemplate.ServiceName)
	}
}

func (wh *AccountWarehouse) determinePrincipalSpec(params *ResourceParams) *principalSpec {
	princSpec := &principalSpec{
		damPrincipalARN: wh.svcUserARN,
		account:         wh.account,
		params:          params,
	}

	if params.TTL > TemporaryCredMaxTTL {
		princSpec.pType = userType
	} else {
		princSpec.pType = roleType
	}
	return princSpec
}

func (wh *AccountWarehouse) ensureTokenResult(ctx context.Context, principalARN string, princSpec *principalSpec) (*ResourceTokenResult, error) {
	switch princSpec.pType {
	case userType:
		return wh.ensureAccessKeyResult(ctx, principalARN, princSpec)
	case roleType:
		return wh.createTempCredentialResult(principalARN, princSpec.params)
	default:
		return nil, fmt.Errorf("cannot generate token for invalid spec with [%v] principal type", princSpec.pType)
	}
}

func(wh *AccountWarehouse) createTempCredentialResult(principalARN string, params *ResourceParams) (*ResourceTokenResult, error) {
	userID := convertDamUserIDtoAwsName(params.UserID, wh.svcUserARN)
	aro, err := wh.assumeRole(userID, principalARN, params.TTL)
	if err != nil {
		return nil, err
	}
	return &ResourceTokenResult{
		Account:         *aro.AssumedRoleUser.Arn,
		AccessKeyID:     *aro.Credentials.AccessKeyId,
		SecretAccessKey: *aro.Credentials.SecretAccessKey,
		SessionToken:    *aro.Credentials.SessionToken,
		Format:          "aws",
	}, nil
}

func (wh *AccountWarehouse) ensureAccessKeyResult(ctx context.Context, principalARN string, princSpec *principalSpec) (*ResourceTokenResult, error) {
	accessKey, err := wh.ensureAccessKey(princSpec)
	if err != nil {
		return nil, err
	}
	return &ResourceTokenResult{
		Account:         principalARN,
		AccessKeyID:     *accessKey.AccessKeyId,
		SecretAccessKey: *accessKey.SecretAccessKey,
		Format:          "aws",
	}, nil
}

func(wh *AccountWarehouse) ensurePrincipal(princSpec *principalSpec) (string, error) {
	switch princSpec.pType {
	case userType:
		return wh.ensureUser(princSpec)
	case roleType:
		return wh.ensureRole(princSpec)
	default:
		panic(fmt.Sprintf("unknown princpal type [%v]", princSpec.pType))
	}
}

func(wh *AccountWarehouse) ensurePolicy(spec *policySpec) error {
	if len(spec.rSpecs) == 0 {
		return fmt.Errorf("cannot have policy without any resources")
	}
	switch spec.principal.pType {
	case userType:
		return wh.ensureUserPolicy(spec)
	case roleType:
		return wh.ensureRolePolicy(spec)
	default:
		return fmt.Errorf("cannot generate policy for invalid spec with [%v] principal type", spec.principal.pType)
	}
}

func convertDamUserIDtoAwsName(damUserID, damSvcARN string) string{
	parts := strings.SplitN(damUserID, "|", 2)
	sessionName := parts[0] + "@" + extractUserName(damSvcARN)
	maxLen := 64
	if len(sessionName) < 64 {
		maxLen = len(sessionName)
	}
	return sessionName[0:maxLen]
}

func(wh *AccountWarehouse) assumeRole(sessionName string, roleARN string, ttl time.Duration) (*sts.AssumeRoleOutput, error) {
	var aro *sts.AssumeRoleOutput
	f := func() error {
		var err error
		aro, err = wh.apiClient.AssumeRole(&sts.AssumeRoleInput{
			RoleArn:         aws.String(roleARN),
			RoleSessionName: aws.String(sessionName),
			DurationSeconds: toSeconds(ttl),
		})

		return err
	}

	err := backoff.Retry(f, exponentialBackoff)
	if err != nil {
		return nil, fmt.Errorf("unable to assume role %s: %v", roleARN, err)
	}
	return aro, nil
}

func (wh *AccountWarehouse) ensureAccessKey(princSpec *principalSpec) (*iam.AccessKey, error) {
	userID := princSpec.getID()
	kres, err := wh.apiClient.CreateAccessKey(&iam.CreateAccessKeyInput{UserName: aws.String(userID)})
	if err != nil {
		return nil, fmt.Errorf("unable to create access key for user %s: %v", userID, err)
	}

	return kres.AccessKey, nil
}

type policy struct {
	Version   string    `json:"Version"`
	Statement statement `json:"Statement"`
}

type statement struct {
	Effect    string                 `json:"Effect"`
	Principal map[string]interface{} `json:"Principal,omitempty"`
	Action    []string               `json:"Action"`
	Resource  []string               `json:"Resource,omitempty"`
	Condition map[string]interface{} `json:"Condition,omitempty"`
}

func(wh *AccountWarehouse) ensureRolePolicy(spec *policySpec) error {
	// FIXME handle versioning
	resourceARNs := resourceARNToArray(spec.rSpecs)
	policy := &policy{
		Version:   "2012-10-17",
		Statement: statement{
			Effect:   "Allow",
			Action:   spec.params.TargetRoles,
			Resource: resourceARNs,
		},
	}
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("error creating AWS policy JSON: %v", err)
	}

	f := func() error { return wh.putRolePolicy(spec, string(policyJSON)) }
	return backoff.Retry(f, exponentialBackoff)
}

func (wh *AccountWarehouse) putRolePolicy(spec *policySpec, policy string) error {
	_, err := wh.apiClient.PutRolePolicy(&iam.PutRolePolicyInput{
		PolicyName:     aws.String(spec.getID()),
		RoleName:       aws.String(spec.principal.getID()),
		PolicyDocument: aws.String(policy),
	})
	if err != nil {
		return fmt.Errorf("unable to create AWS role policy %s: %v", spec.principal.getID(), err)
	}
	return nil
}

func(wh *AccountWarehouse) ensureUserPolicy(spec *policySpec) error {
	// FIXME handle versioning
	resources := resourceARNToArray(spec.rSpecs)
	policy := &policy{
		Version:   "2012-10-17",
		Statement: statement{
			Effect:   "Allow",
			Action:   spec.params.TargetRoles,
			Resource: resources,
			Condition: map[string]interface{}{
				"DateLessThanEquals": map[string]string {
					"aws:CurrentTime": (time.Now().Add(spec.params.TTL)).Format(time.RFC3339),
				},
			},
		},
	}
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("error creating AWS policy JSON: %v", err)
	}

	f := func() error { return wh.putUserPolicy(spec, string(policyJSON)) }
	return backoff.Retry(f, exponentialBackoff)
}

func(wh *AccountWarehouse) putUserPolicy(spec *policySpec, policy string) error {
	_, err := wh.apiClient.PutUserPolicy(&iam.PutUserPolicyInput{
		PolicyName:     aws.String(spec.getID()),
		UserName:       aws.String(spec.principal.getID()),
		PolicyDocument: aws.String(policy),
	})
	if err != nil {
		return fmt.Errorf("unable to create AWS user policy %s: %v", spec.principal.getID(), err)
	}
	return nil
}


// ensures user is created and returns non-empty user ARN if successful
func(wh *AccountWarehouse) ensureUser(spec *principalSpec) (string, error) {
	guo, err := wh.apiClient.GetUser(&iam.GetUserInput{UserName: aws.String(spec.getID())})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() == iam.ErrCodeNoSuchEntityException {
			cuo, err := wh.apiClient.CreateUser(&iam.CreateUserInput{
				UserName: aws.String(spec.getID()),
				// FIXME Make prefix configurable for different dam deployments GcpServiceAccountProject
				Path: aws.String("/ddap/"),
			})
			if err != nil {
				return "", fmt.Errorf("unable to create IAM user %s: %v", spec.getID(), err)
			}
			return *cuo.User.Arn, nil
		}
		return "", fmt.Errorf("unable to send AWS IAM request for user %s: %v", spec.getID(), err)
	}
	return *guo.User.Arn, nil
}

func(wh *AccountWarehouse) ensureRole(spec *principalSpec) (string, error) {
	gro, err := wh.apiClient.GetRole(&iam.GetRoleInput{RoleName: aws.String(spec.getID())})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() == iam.ErrCodeNoSuchEntityException {
			policy := &policy{
				Version:   "2012-10-17",
				Statement: statement{
					Effect:    "Allow",
					Principal: map[string]interface{}{
						"AWS": spec.damPrincipalARN,
					},
					Action:   []string{"sts:AssumeRole"},
				},
			}
			policyJSON, err := json.Marshal(policy)
			if err != nil {
				return "", fmt.Errorf("error creating AWS policy JSON: %v", err)
			}

			cro, err := wh.apiClient.CreateRole(&iam.CreateRoleInput{
				AssumeRolePolicyDocument: aws.String(string(policyJSON)),
				RoleName:                 aws.String(spec.getID()),
				// FIXME should get path from config
				Path:                     aws.String("/ddap/"),
				MaxSessionDuration:       toSeconds(TemporaryCredMaxTTL),
				Tags: []*iam.Tag{
					{Key: aws.String("DamResource"), Value: aws.String(spec.params.DamResourceID)},
					{Key: aws.String("DamView"), Value: aws.String(spec.params.DamViewID)},
					{Key: aws.String("DamRole"), Value: aws.String(spec.params.DamRoleID)},
				},
			})
			if err != nil {
				return "", fmt.Errorf("unable to create AWS role %s: %v", spec.getID(), err)
			}
			return *cro.Role.Arn, nil
		}
		return "", fmt.Errorf("unable to retrieve AWS role %s: %v", spec.getID(), err)
	}
	return *gro.Role.Arn, nil
}

func extractUserName(userARN string) string {
	arnParts := strings.Split(userARN, ":")
	pathParts := strings.Split(arnParts[5], "/")

	return pathParts[len(pathParts)-1]
}

func toSeconds(duration time.Duration) *int64 {
	seconds := duration.Nanoseconds() / time.Second.Nanoseconds()
	return &seconds
}

func resourceARNToArray(rSpecs []*resourceSpec) []string {
	arns := make([]string, len(rSpecs))
	for i, rSpec := range rSpecs {
		arns[i] = rSpec.arn
	}

	return arns
}
