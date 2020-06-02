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
	"context"
	"fmt"
	v1 "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/cenkalti/backoff"
	"strings"
	"time"
)

const (
	TemporaryCredMaxTtl = 12 * time.Hour
	S3ItemFormat        = "s3bucket"
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

type ApiClient interface {
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
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string
}

// AccountWarehouse is used to create AWS IAM Users and temporary credentials
type AccountWarehouse struct {
	svcUserArn string
	apiClient  ApiClient
}

// NewWarehouse creates a new AccountWarehouse using the provided client
// and options.
func NewWarehouse(_ context.Context, awsClient ApiClient) (*AccountWarehouse, error) {
	wh := &AccountWarehouse{
		apiClient: awsClient,
	}
	if gcio, err := awsClient.GetCallerIdentity(&sts.GetCallerIdentityInput{}); err != nil {
		return nil, err
	} else {
		wh.svcUserArn = *gcio.Arn
	}

	return wh, nil
}

func (wh *AccountWarehouse) GetAwsAccount() string {
	return extractAccount(wh.svcUserArn)
}

type ResourceParams struct {
	UserId                string
	Ttl                   time.Duration
	MaxKeyTtl             time.Duration
	ManagedKeysPerAccount int
	Vars                  map[string]string
	TargetRoles           []string
	TargetScopes          []string
	DamResourceId         string
	DamViewId             string
	DamRoleId             string
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
	damPrincipalArn string
	params          *ResourceParams
}

type policySpec struct {
	principal *principalSpec
	rSpecs    []*resourceSpec
	params    *ResourceParams
}

func (spec *policySpec) getId() string {
	return spec.principal.getDamResourceViewRoleId()
}

func (spec *principalSpec) getId() string {
	switch spec.pType {
	case userType:
		return convertDamUserIdToAwsName(spec.params.UserId, spec.damPrincipalArn)
	case roleType:
		return spec.getDamResourceViewRoleId()
	default:
		panic(fmt.Sprintf("cannot get ID for princpal type [%v]", spec.pType))
	}
}

func (spec *principalSpec) getDamResourceViewRoleId() string {
	return fmt.Sprintf("%s,%s,%s@%s", spec.params.DamResourceId, spec.params.DamViewId, spec.params.DamRoleId, extractUserName(spec.damPrincipalArn))
}

func (spec *principalSpec) getArn() string {
	switch spec.pType {
	case userType:
		return fmt.Sprintf("arn:aws:iam::%s:user/%s", extractAccount(spec.damPrincipalArn), spec.getId())
	case roleType:
		return fmt.Sprintf("arn:aws:iam::%s:role/%s", extractAccount(spec.damPrincipalArn), spec.getId())
	default:
		panic(fmt.Sprintf("cannot get ID for princpal type [%v]", spec.pType))
	}
}

func calculateDbuserArn(clusterArn string, userName string) string {
	parts := strings.Split(clusterArn, ":")

	return fmt.Sprintf( "%s:%s:%s:%s:%s:dbuser:%s/%s", parts[0], parts[1], parts[2], parts[3], parts[4], parts[6], userName)
}

func extractAccount(arn string) string {
	parts := strings.Split(arn, ":")
	return parts[4]
}

func extractClusterName(arn string) string {
	parts := strings.Split(arn, ":")
	return parts[6]
}

func extractDBGroupName(arn string) string {
	arnParts := strings.Split(arn, ":")
	pathParts := strings.Split(arnParts[6], "/")

	return pathParts[len(pathParts)-1]
}

// MintTokenWithTTL returns an AccountKey or an AccessToken depending on the TTL requested.
func (wh *AccountWarehouse) MintTokenWithTTL(ctx context.Context, params *ResourceParams) (*ResourceTokenResult, error) {
	if params.Ttl > params.MaxKeyTtl {
		return nil, fmt.Errorf("given ttl [%s] is greater than max ttl [%s]", params.Ttl, params.MaxKeyTtl)
	}

	princSpec := determinePrincipalSpec(wh.svcUserArn, params)

	rSpecs, err := wh.determineResourceSpecs(params)
	if err != nil {
		return nil, err
	}
	polSpec := &policySpec{
		principal: princSpec,
		rSpecs:    rSpecs,
		params:    params,
	}

	principalArn, err := wh.ensurePrincipal(princSpec)
	if err != nil {
		return nil, err
	}
	err = wh.ensurePolicy(polSpec)
	if err != nil {
		return nil, err
	}

	return wh.ensureTokenResult(ctx, principalArn, princSpec)
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
		clusterArn, ok := params.Vars["cluster"]
		if !ok {
			return nil, fmt.Errorf("no cluster specified")
		}
		clusterSpec := &resourceSpec{
			rType: otherRType,
			arn:   clusterArn,
			id:    extractClusterName(clusterArn),
		}
		dbuser := convertDamUserIdToAwsName(params.UserId, wh.svcUserArn)
		userSpec := &resourceSpec{
			rType: otherRType,
			arn:   calculateDbuserArn(clusterArn, dbuser),
			id:    dbuser,
		}
		group, ok := params.Vars["group"]
		if ok {
			return []*resourceSpec{
				clusterSpec,
				userSpec,
				{
					rType: otherRType,
					arn:   group,
					id:    extractDBGroupName(group),
				},
			}, nil
		} else {
			return []*resourceSpec{clusterSpec, userSpec}, nil
		}

	default:
		return nil, fmt.Errorf("unrecognized item format [%s] for AWS target adapter", params.ServiceTemplate.ServiceName)
	}
}

func determinePrincipalSpec(svcUserArn string, params *ResourceParams) *principalSpec {
	princSpec := &principalSpec{
		damPrincipalArn: svcUserArn,
		params:          params,
	}

	if params.Ttl > TemporaryCredMaxTtl {
		princSpec.pType = userType
	} else {
		princSpec.pType = roleType
	}
	return princSpec
}

func (wh *AccountWarehouse) ensureTokenResult(ctx context.Context, principalArn string, princSpec *principalSpec) (*ResourceTokenResult, error) {
	switch princSpec.pType {
	case userType:
		return wh.ensureAccessKeyResult(ctx, principalArn, princSpec)
	case roleType:
		return wh.createTempCredentialResult(principalArn, princSpec.params)
	default:
		return nil, fmt.Errorf("cannot generate token for invalid spec with [%v] principal type", princSpec.pType)
	}
}

func(wh *AccountWarehouse) createTempCredentialResult(principalArn string, params *ResourceParams) (*ResourceTokenResult, error) {
	userId := convertDamUserIdToAwsName(params.UserId, wh.svcUserArn)
	aro, err := wh.assumeRole(userId, principalArn, params.Ttl)
	if err != nil {
		return nil, err
	}
	return &ResourceTokenResult{
		Account: *aro.AssumedRoleUser.Arn,
		AccessKeyId:   *aro.Credentials.AccessKeyId,
		SecretAccessKey:   *aro.Credentials.SecretAccessKey,
		SessionToken:   *aro.Credentials.SessionToken,
		Format:  "aws",
	}, nil
}

func (wh *AccountWarehouse) ensureAccessKeyResult(ctx context.Context, principalArn string, princSpec *principalSpec) (*ResourceTokenResult, error) {
	accessKey, err := wh.ensureAccessKey(princSpec)
	if err != nil {
		return nil, err
	}
	return &ResourceTokenResult{
		Account: principalArn,
		AccessKeyId: *accessKey.AccessKeyId,
		SecretAccessKey: *accessKey.SecretAccessKey,
		Format:  "aws",
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
	} else {
		switch spec.principal.pType {
		case userType:
			return wh.ensureUserPolicy(spec)
		case roleType:
			return wh.ensureRolePolicy(spec)
		default:
			return fmt.Errorf("cannot generate policy for invalid spec with [%v] principal type", spec.principal.pType)
		}
	}
}

func convertDamUserIdToAwsName(damUserId, damSvcArn string) string{
	parts := strings.SplitN(damUserId, "|", 2)
	sessionName := parts[0] + "@" + extractUserName(damSvcArn)
	maxLen := 64
	if len(sessionName) < 64 {
		maxLen = len(sessionName)
	}
	return sessionName[0:maxLen]
}

func(wh *AccountWarehouse) assumeRole(sessionName string, roleArn string, ttl time.Duration) (*sts.AssumeRoleOutput, error) {
	var aro *sts.AssumeRoleOutput
	f := func() error {
		var err error
		aro, err = wh.apiClient.AssumeRole(&sts.AssumeRoleInput{
			RoleArn:         aws.String(roleArn),
			RoleSessionName: aws.String(sessionName),
			DurationSeconds: toSeconds(ttl),
		})

		return err
	}

	err := backoff.Retry(f, exponentialBackoff)
	if err != nil {
		return nil, fmt.Errorf("unable to assume role %s: %v", roleArn, err)
	} else {
		return aro, nil
	}
}

func (wh *AccountWarehouse) ensureAccessKey(princSpec *principalSpec) (*iam.AccessKey, error) {
	userId := princSpec.getId()
	kres, err := wh.apiClient.CreateAccessKey(&iam.CreateAccessKeyInput{UserName: aws.String(userId)})
	if err != nil {
		return nil, fmt.Errorf("unable to create access key for user %s: %v", userId, err)
	}

	return kres.AccessKey, nil
}

func(wh *AccountWarehouse) ensureRolePolicy(spec *policySpec) error {
	// FIXME handle versioning
	actions := valuesToJsonStringArray(spec.params.TargetRoles)
	resourceArns := resourceArnsToJsonStringArray(spec.rSpecs)
	// FIXME use serialization library
	policy := fmt.Sprintf(
		`{
								"Version":"2012-10-17",
								"Statement":
								{
									"Effect":"Allow",
									"Action":%s,
									"Resource":%s
								}
							}`, actions, resourceArns)
	f := func() error { return wh.putRolePolicy(spec, policy) }
	return backoff.Retry(f, exponentialBackoff)
}

func (wh *AccountWarehouse) putRolePolicy(spec *policySpec, policy string) error {
	_, err := wh.apiClient.PutRolePolicy(&iam.PutRolePolicyInput{
		PolicyName:     aws.String(spec.getId()),
		RoleName:       aws.String(spec.principal.getId()),
		PolicyDocument: aws.String(policy),
	})
	if err != nil {
		return fmt.Errorf("unable to create AWS user policy %s: %v", spec.principal.getId(), err)
	} else {
		return nil
	}
}

func(wh *AccountWarehouse) ensureUserPolicy(spec *policySpec) error {
	// FIXME handle versioning
	actions := valuesToJsonStringArray(spec.params.TargetRoles)
	resources := resourceArnsToJsonStringArray(spec.rSpecs)
	// FIXME use serialization library
	policy := fmt.Sprintf(
		`{
								"Version":"2012-10-17",
								"Statement":
								{
									"Effect":"Allow",
									"Action":%s,
									"Resource":%s,
									"Condition": {
										"DateLessThanEquals": {"aws:CurrentTime": "%s"}
									}
								}
							}`, actions, resources, (time.Now().Add(spec.params.Ttl)).Format(time.RFC3339) )
	f := func() error { return wh.putUserPolicy(spec, policy) }
	return backoff.Retry(f, exponentialBackoff)
}

func(wh *AccountWarehouse) putUserPolicy(spec *policySpec, policy string) error {
	_, err := wh.apiClient.PutUserPolicy(&iam.PutUserPolicyInput{
		PolicyName:     aws.String(spec.getId()),
		UserName:       aws.String(spec.principal.getId()),
		PolicyDocument: aws.String(policy),
	})
	if err != nil {
		return fmt.Errorf("unable to create AWS user policy %s: %v", spec.principal.getId(), err)
	} else {
		return nil
	}
}


// ensures user is created and returns non-empty user ARN if successful
func(wh *AccountWarehouse) ensureUser(spec *principalSpec) (string, error) {
	if guo, err := wh.apiClient.GetUser(&iam.GetUserInput{UserName: aws.String(spec.getId())}); err != nil {
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() == iam.ErrCodeNoSuchEntityException {
			cuo, err := wh.apiClient.CreateUser(&iam.CreateUserInput{
				UserName: aws.String(spec.getId()),
				// FIXME Make prefix configurable for different dam deployments GcpServiceAccountProject
				Path: aws.String("/ddap/"),
			})
			if err != nil {
				return "", fmt.Errorf("unable to create IAM user %s: %v", spec.getId(), err)
			} else {
				return *cuo.User.Arn, nil
			}
		} else {
			return "", fmt.Errorf("unable to send AWS IAM request for user %s: %v", spec.getId(), err)
		}
	} else {
		return *guo.User.Arn, nil
	}
}

func(wh *AccountWarehouse) ensureRole(spec *principalSpec) (string, error) {
	if gro, err := wh.apiClient.GetRole(&iam.GetRoleInput{RoleName: aws.String(spec.getId())}); err != nil {
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() == iam.ErrCodeNoSuchEntityException {
			policy := fmt.Sprintf(
				`{
								"Version":"2012-10-17",
								"Statement":
								{
									"Effect":"Allow",
									"Principal": { "AWS": "%s" },
									"Action": "sts:AssumeRole"
								}
							}`, spec.damPrincipalArn)
			cro, err := wh.apiClient.CreateRole(&iam.CreateRoleInput{
				AssumeRolePolicyDocument: aws.String(policy),
				RoleName:                 aws.String(spec.getId()),
				// FIXME should get path from config
				Path:                     aws.String("/ddap/"),
				MaxSessionDuration:       toSeconds(TemporaryCredMaxTtl),
				Tags: []*iam.Tag{
					{Key: aws.String("DamResource"), Value: aws.String(spec.params.DamResourceId)},
					{Key: aws.String("DamView"), Value: aws.String(spec.params.DamViewId)},
					{Key: aws.String("DamRole"), Value: aws.String(spec.params.DamRoleId)},
				},
			})
			if err != nil {
				return "", fmt.Errorf("unable to create AWS role %s: %v", spec.getId(), err)
			} else {
				return *cro.Role.Arn, nil
			}
		} else {
			return "", fmt.Errorf("unable to retrieve AWS role %s: %v", spec.getId(), err)
		}
	} else {
		return *gro.Role.Arn, nil
	}
}

func extractUserName(userArn string) string {
	arnParts := strings.Split(userArn, ":")
	pathParts := strings.Split(arnParts[5], "/")

	return pathParts[len(pathParts)-1]
}

func toSeconds(duration time.Duration) *int64 {
	seconds := duration.Nanoseconds() / time.Second.Nanoseconds()
	return &seconds
}

func resourceArnsToJsonStringArray(rSpecs []*resourceSpec) string {
	arns := make([]string, len(rSpecs))
	for i, rSpec := range rSpecs {
		arns[i] = rSpec.arn
	}

	return valuesToJsonStringArray(arns)
}

func valuesToJsonStringArray(targetRoles []string) string {
	builder := strings.Builder{}
	builder.WriteByte('[')
	for i, role := range targetRoles {
		builder.WriteByte('"')
		builder.WriteString(role)
		builder.WriteByte('"')
		if (i + 1) < len(targetRoles) {
			builder.WriteByte(',')
		}
	}
	builder.WriteByte(']')

	return builder.String()
}
