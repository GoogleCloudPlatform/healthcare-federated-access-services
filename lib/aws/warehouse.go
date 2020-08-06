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
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws" /* copybara-comment */
	"github.com/aws/aws-sdk-go/aws/awserr" /* copybara-comment */
	"github.com/aws/aws-sdk-go/service/iam" /* copybara-comment */
	"github.com/aws/aws-sdk-go/service/sts" /* copybara-comment */
	"github.com/cenkalti/backoff" /* copybara-comment */
	"bitbucket.org/creachadair/stringset" /* copybara-comment */
	"github.com/pborman/uuid" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds" /* copybara-comment: clouds */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/timeutil" /* copybara-comment: timeutil */

	glog "github.com/golang/glog" /* copybara-comment */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
)

const (
	// TemporaryCredMaxTTL is the maximum TTL for an AWS access token.
	TemporaryCredMaxTTL = 12 * time.Hour
	// S3ItemFormat is the canonical item format identifier for S3 buckets.
	S3ItemFormat = "s3bucket"
	// RedshiftItemFormat is the canonical item format identifier for Redshift clusters.
	RedshiftItemFormat = "redshift"
	// RedshiftConsoleItemFormat is the canonical item format identifier for the Redshift console.
	RedshiftConsoleItemFormat = "redshift-console"
	// HumanInterfacePrefix is the canonical prefix for interface URNs that grant console access to AWS resources.
	HumanInterfacePrefix = "web:aws:"
)

type principalType int

const (
	userType principalType = iota
	roleType
)

type credentialType int

const (
	temporaryKey credentialType = iota
	permanentKey
	usernamePassword
)

type resourceType int

const (
	otherRType resourceType = iota
	bucketType
	clusterUserType
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
	ListUserPolicies(input *iam.ListUserPoliciesInput) (*iam.ListUserPoliciesOutput, error)
	PutUserPolicy(input *iam.PutUserPolicyInput) (*iam.PutUserPolicyOutput, error)
	DeleteUserPolicy(input *iam.DeleteUserPolicyInput) (*iam.DeleteUserPolicyOutput, error)
	GetUser(input *iam.GetUserInput) (*iam.GetUserOutput, error)
	CreateUser(input *iam.CreateUserInput) (*iam.CreateUserOutput, error)
	DeleteUser(input *iam.DeleteUserInput) (*iam.DeleteUserOutput, error)
	GetRole(input *iam.GetRoleInput) (*iam.GetRoleOutput, error)
	CreateRole(input *iam.CreateRoleInput) (*iam.CreateRoleOutput, error)
	CreateLoginProfile(input *iam.CreateLoginProfileInput) (*iam.CreateLoginProfileOutput, error)
	UpdateLoginProfile(input *iam.UpdateLoginProfileInput) (*iam.UpdateLoginProfileOutput, error)
	GetLoginProfile(input *iam.GetLoginProfileInput) (*iam.GetLoginProfileOutput, error)
	DeleteLoginProfile(input *iam.DeleteLoginProfileInput) (*iam.DeleteLoginProfileOutput, error)
}

// ResourceTokenResult is returned from MintTokenWithTTL for aws adapter.
type ResourceTokenResult struct {
	Account         string
	PrincipalARN    string
	Format          string
	AccessKeyID     *string
	SecretAccessKey *string
	SessionToken    *string
	UserName        *string
	Password        *string
}

// AccountWarehouse is used to create AWS IAM Users and temporary credentials
type AccountWarehouse struct {
	account     string
	svcUserARN  string
	svcUserName string
	apiClient   APIClient
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
	wh.svcUserName, err = extractUserName(wh.svcUserARN)
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

// GetServiceAccounts returns IAM users created by this warehouse in the warehouse AWS account.
func (wh *AccountWarehouse) GetServiceAccounts(ctx context.Context, _ string) (<-chan *clouds.Account, error) {
	c := make(chan *clouds.Account)
	go func() {
		defer close(c)
		f := func(acct *iam.User) error {
			a := &clouds.Account{
				ID:          aws.StringValue(acct.UserName),
				DisplayName: aws.StringValue(acct.UserName),
			}
			select {
			case c <- a:
			case <-ctx.Done():
				return ctx.Err()
			}
			return nil
		}
		// TODO: get PathPrefix from config
		accounts, err := wh.apiClient.ListUsers(&iam.ListUsersInput{
			PathPrefix: aws.String("/ddap/"),
		})
		if err != nil {
			glog.Errorf("getting users list: %v", err)
			return
		}
		users := accounts.Users
		for _, user := range users {
			if err := f(user); err != nil {
				glog.Errorf("getting user accounts list: %v", err)
				return
			}
		}

	}()
	return c, nil
}

// RemoveServiceAccount removes an AWS IAM user (project parameter is ignored).
func (wh *AccountWarehouse) RemoveServiceAccount(_ context.Context, _, userName string) error {
	// delete login profile
	var err error
	_, err = wh.apiClient.GetLoginProfile(&iam.GetLoginProfileInput{UserName: aws.String(userName)})
	if err == nil {
		_, err = wh.apiClient.DeleteLoginProfile(&iam.DeleteLoginProfileInput{UserName: aws.String(userName)})
		if err != nil {
			return fmt.Errorf("unable to delete AWS user %s login profile: %v", userName, err)
		}
	} else if aerr, ok := err.(awserr.Error); !ok || aerr.Code() != iam.ErrCodeNoSuchEntityException {
		return fmt.Errorf("error looking up login profile while attempting to delete AWS user %s: %v", userName, aerr)
	}

	// delete access keys
	listKeysOutput, err := wh.apiClient.ListAccessKeys(&iam.ListAccessKeysInput{UserName: aws.String(userName)})
	// gather all keys before deleting
	keys := make([]*iam.AccessKeyMetadata, 0)
	for err == nil && listKeysOutput != nil {
		for _, keyData := range listKeysOutput.AccessKeyMetadata {
			keys = append(keys, keyData)
		}
		if *listKeysOutput.IsTruncated {
			listKeysOutput, err = wh.apiClient.ListAccessKeys(&iam.ListAccessKeysInput{UserName: aws.String(userName), Marker: listKeysOutput.Marker})
		} else {
			listKeysOutput = nil
		}
	}
	if err != nil {
		return fmt.Errorf("unable to list keys for user %s: %v", userName, err)
	}

	for _, keyData := range keys {
		_, err = wh.apiClient.DeleteAccessKey(&iam.DeleteAccessKeyInput{
			AccessKeyId: keyData.AccessKeyId,
			UserName:    keyData.UserName,
		})
		if err != nil {
			return fmt.Errorf("unable to delete access key %s for AWS user %s: %v", *keyData.AccessKeyId, *keyData.UserName, err)
		}
	}

	// delete inline policies
	userPolicyOutput, err := wh.apiClient.ListUserPolicies(&iam.ListUserPoliciesInput{UserName: aws.String(userName)})
	// gather policies
	policyNames := make([]*string, 0)
	for err == nil && userPolicyOutput != nil {
		for _, policyName := range userPolicyOutput.PolicyNames {
			policyNames = append(policyNames, policyName)
		}
		if *userPolicyOutput.IsTruncated {
			userPolicyOutput, err = wh.apiClient.ListUserPolicies(&iam.ListUserPoliciesInput{
				UserName: aws.String(userName),
				Marker: userPolicyOutput.Marker,
			})
		} else {
			userPolicyOutput = nil
		}
	}
	if err != nil {
		return fmt.Errorf("unable to list policies for AWS user %s: %v", userName, err)
	}
	for _, policyName := range policyNames {
		_, err = wh.apiClient.DeleteUserPolicy(&iam.DeleteUserPolicyInput{
			PolicyName: policyName,
			UserName:   aws.String(userName),
		})
		if err != nil {
			return fmt.Errorf("unable to delete AWS policy %s for AWS user %s: %v", *policyName, userName, err)
		}
	}

	// delete user
	_, err = wh.apiClient.DeleteUser(&iam.DeleteUserInput{UserName: aws.String(userName)})
	if err != nil {
		return fmt.Errorf("delete operation on AWS user %s failed: %v", userName, err)
	}

	return nil
}

// ManageAccountKeys is the main method where key removal happens
func (wh *AccountWarehouse) ManageAccountKeys(_ context.Context, _, accountID string, _, maxKeyTTL time.Duration, now time.Time, keysPerAccount int64) (int, int, error) {
	// A key has expired if key.CreatedDate + maxTTL < now, i.e. key.ValidAfterTime < now - maxTTL
	expired := now.Add(-1 * maxKeyTTL).Format(time.RFC3339)
	accessKeys, err := wh.apiClient.ListAccessKeys(&iam.ListAccessKeysInput{
		UserName: aws.String(accountID),
	})
	if err != nil {
		return 0, 0, fmt.Errorf("error getting aws key list: %v", err)
	}
	keys := accessKeys.AccessKeyMetadata
	var actives []*iam.AccessKeyMetadata
	active := len(keys)
	for _, key := range keys {
		t := aws.TimeValue(key.CreateDate).Format(time.RFC3339)
		if t < expired {
			// Access key deletion
			_, err := wh.apiClient.DeleteAccessKey(&iam.DeleteAccessKeyInput{
				AccessKeyId: key.AccessKeyId,
				UserName:    aws.String(accountID),
			})
			if err != nil {
				return active, len(keys) - active, fmt.Errorf("error deleting aws access key: %v", err)
			}
			active--
			continue
		}
		actives = append(actives, key)
	}

	if int64(len(actives)) < keysPerAccount {
		return active, len(keys) - active, nil
	}

	// Remove earliest expiring keys
	sort.Slice(actives, func(i, j int) bool {
		return aws.TimeValue(actives[i].CreateDate).After(aws.TimeValue(actives[j].CreateDate))
	})
	for _, key := range actives[keysPerAccount:] {
		_, err := wh.apiClient.DeleteAccessKey(&iam.DeleteAccessKeyInput{
			AccessKeyId: key.AccessKeyId,
			UserName:    aws.String(accountID),
		})
		if err != nil {
			return active, len(keys) - active, fmt.Errorf("deleting key: %v", err)
		}
		active--
	}
	return active, len(keys) - active, nil
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
	DamInterfaceID        string
	ServiceTemplate       *pb.ServiceTemplate
}

type resourceSpec struct {
	rType resourceType
	arn   string
}

type principalSpec struct {
	pType principalType
	// Used for roles that must be assumed
	damPrincipalARN      string
	damPrincipalUserName string
	// path must start and end with slash
	path    string
	account string
	params  *ResourceParams
}

type credentialSpec struct {
	cType         credentialType
	principalSpec *principalSpec
	params        *ResourceParams
}

type policySpec struct {
	credSpec *credentialSpec
	rSpecs   []*resourceSpec
	params   *ResourceParams
}

func (spec *policySpec) getID() string {
	return spec.credSpec.principalSpec.getDamResourceViewRoleID()
}

func (spec *policySpec) sessionScoped() bool {
	if spec.credSpec.principalSpec.pType == roleType {
		for _, rSpec := range spec.rSpecs {
			if rSpec.rType == clusterUserType {
				return true
			}
		}
	}

	return false
}

func (spec *principalSpec) getID() string {
	if spec.pType == roleType {
		return spec.getDamResourceViewRoleID()
	}
	return convertDamUserIDtoAwsName(spec.params.UserID, spec.damPrincipalUserName)
}

func (spec *principalSpec) getDamResourceViewRoleID() string {
	return fmt.Sprintf("%s,%s,%s@%s", spec.params.DamResourceID, spec.params.DamViewID, spec.params.DamRoleID, spec.damPrincipalUserName)
}

func (spec *principalSpec) getARN() string {
	if spec.pType == roleType {
		return fmt.Sprintf("arn:aws:iam::%s:role%s%s", spec.account, spec.path, spec.getID())
	}
	return fmt.Sprintf("arn:aws:iam::%s:user%s%s", spec.account, spec.path, spec.getID())
}

func calculateDBuserARN(clusterARN string, userName string) (string, error) {
	parts := strings.Split(clusterARN, ":")
	if len(parts) < 7 {
		return "", fmt.Errorf("argument is not a proper cluster ARN: %s", clusterARN)
	}

	return fmt.Sprintf("%s:%s:%s:%s:%s:dbuser:%s/%s", parts[0], parts[1], parts[2], parts[3], parts[4], parts[6], userName), nil
}

func extractAccount(arn string) (string, error) {
	parts := strings.Split(arn, ":")
	if len(parts) < 5 {
		return "", fmt.Errorf("argument is not a proper ARN: %s", arn)
	}

	return parts[4], nil
}

// MintTokenWithTTL returns an AccountKey or an AccessToken depending on the TTL requested.
func (wh *AccountWarehouse) MintTokenWithTTL(ctx context.Context, params *ResourceParams) (*ResourceTokenResult, error) {
	if params.TTL > params.MaxKeyTTL {
		return nil, fmt.Errorf("given ttl [%s] is greater than max ttl [%s]", params.TTL, params.MaxKeyTTL)
	}

	credSpec := wh.determineCredentialSpec(params)

	rSpecs, err := wh.determineResourceSpecs(params)
	if err != nil {
		return nil, err
	}
	polSpec := &policySpec{
		credSpec: credSpec,
		rSpecs:   rSpecs,
		params:   params,
	}

	principalARN, err := wh.ensurePrincipal(credSpec.principalSpec)
	if err != nil {
		return nil, err
	}

	return wh.ensureTokenResult(ctx, principalARN, polSpec)
}

func (wh *AccountWarehouse) determineResourceSpecs(params *ResourceParams) ([]*resourceSpec, error) {
	switch params.ServiceTemplate.ServiceName {
	case S3ItemFormat:
		bucket, ok := params.Vars["bucket"]
		if !ok {
			return nil, fmt.Errorf("no bucket specified")
		}
		paths, ok := params.Vars["paths"]
		if !ok || paths == "" || paths == "*" || paths == "/*" {
			return []*resourceSpec{
				{
					arn:   fmt.Sprintf("arn:aws:s3:::%s/*", bucket),
					rType: bucketType,
				},
				{
					arn:   fmt.Sprintf("arn:aws:s3:::%s", bucket),
					rType: bucketType,
				},
			}, nil
		}
		uniquePaths := stringset.New(strings.Split(paths, ";")...)
		var resourceSpecs []*resourceSpec
		for _, v := range uniquePaths.Elements() {
			resourceSpecs = append(resourceSpecs, &resourceSpec{
				arn:   fmt.Sprintf("arn:aws:s3:::%s%s", bucket, v),
				rType: bucketType,
			})
		}
		return resourceSpecs, nil
	case RedshiftItemFormat:
		clusterARN, ok := params.Vars["cluster"]
		if !ok {
			return nil, fmt.Errorf("no cluster specified")
		}
		clusterSpec := &resourceSpec{
			rType: otherRType,
			arn:   clusterARN,
		}
		dbUser := convertDamUserIDtoAwsName(params.UserID, wh.svcUserName)
		dbUserARN, err := calculateDBuserARN(clusterARN, dbUser)
		if err != nil {
			return nil, err
		}
		userSpec := &resourceSpec{
			rType: clusterUserType,
			arn:   dbUserARN,
		}
		group, ok := params.Vars["group"]
		if ok {
			return []*resourceSpec{
				clusterSpec,
				userSpec,
				{
					rType: otherRType,
					arn:   group,
				},
			}, nil
		}
		return []*resourceSpec{clusterSpec, userSpec}, nil
	case RedshiftConsoleItemFormat:
		packedResources, ok := params.Vars["resources"]
		var resources []string
		if ok {
			resources = strings.Split(packedResources, ";")
		} else {
			resources = []string{"*"}
		}

		var specs []*resourceSpec
		for _, res := range resources {
			specs = append(specs, &resourceSpec{
				rType: otherRType,
				arn:   res,
			})
		}

		return specs, nil

	default:
		return nil, fmt.Errorf("unrecognized item format [%s] for AWS target adapter", params.ServiceTemplate.ServiceName)
	}
}

func (wh *AccountWarehouse) determineCredentialSpec(params *ResourceParams) *credentialSpec {
	credentialSpec := &credentialSpec{params: params}
	if strings.HasPrefix(params.DamInterfaceID, HumanInterfacePrefix) {
		credentialSpec.cType = usernamePassword
	} else if params.TTL > TemporaryCredMaxTTL {
		credentialSpec.cType = permanentKey
	} else {
		credentialSpec.cType = temporaryKey
	}
	credentialSpec.principalSpec = wh.determinePrincipalSpec(credentialSpec)

	return credentialSpec
}

func (wh *AccountWarehouse) determinePrincipalSpec(credSpec *credentialSpec) *principalSpec {
	params := credSpec.params
	princSpec := &principalSpec{
		damPrincipalARN:      wh.svcUserARN,
		damPrincipalUserName: wh.svcUserName,
		account:              wh.account,
		params:               params,
		// TODO: Make prefix configurable for different dam deployments
		path: "/ddap/",
	}

	if credSpec.cType == temporaryKey {
		princSpec.pType = roleType
	} else {
		princSpec.pType = userType
	}

	return princSpec
}

func (wh *AccountWarehouse) ensureTokenResult(ctx context.Context, principalARN string, polSpec *policySpec) (*ResourceTokenResult, error) {
	err := wh.ensureIdentityPolicy(polSpec)
	if err != nil {
		return nil, err
	}

	switch polSpec.credSpec.cType {
	case permanentKey:
		return wh.ensureAccessKeyResult(ctx, principalARN, polSpec.credSpec.principalSpec)
	case temporaryKey:
		return wh.createTempCredentialResult(polSpec)
	case usernamePassword:
		return wh.createUsernamePasswordResult(principalARN)
	default:
		return nil, fmt.Errorf("cannot generate token for invalid spec with [%v] credential type", polSpec.credSpec.cType)
	}
}

func (wh *AccountWarehouse) createTempCredentialResult(polSpec *policySpec) (*ResourceTokenResult, error) {
	aro, err := wh.assumeRole(polSpec)
	if err != nil {
		return nil, err
	}
	return &ResourceTokenResult{
		Account:         wh.account,
		PrincipalARN:    *aro.AssumedRoleUser.Arn,
		AccessKeyID:     aro.Credentials.AccessKeyId,
		SecretAccessKey: aro.Credentials.SecretAccessKey,
		SessionToken:    aro.Credentials.SessionToken,
		Format:          "aws/session",
	}, nil
}

func (wh *AccountWarehouse) ensureAccessKeyResult(ctx context.Context, principalARN string, princSpec *principalSpec) (*ResourceTokenResult, error) {
	accessKey, err := wh.ensureAccessKey(ctx, princSpec, wh.svcUserARN)
	if err != nil {
		return nil, err
	}
	return &ResourceTokenResult{
		Account:         wh.account,
		PrincipalARN:    principalARN,
		AccessKeyID:     accessKey.AccessKeyId,
		SecretAccessKey: accessKey.SecretAccessKey,
		Format:          "aws/key",
	}, nil
}

func (wh *AccountWarehouse) createUsernamePasswordResult(principalARN string) (*ResourceTokenResult, error) {
	userName, err := extractUserName(principalARN)
	if err != nil {
		return nil, fmt.Errorf("generated principal ARN is invalid: %v", err)
	}

	password, err := wh.ensureLoginProfile(userName)
	if err != nil {
		return nil, err
	}

	return &ResourceTokenResult{
		Account:      wh.account,
		PrincipalARN: principalARN,
		UserName:     &userName,
		Password:     &password,
		Format:       "aws",
	}, nil
}

func (wh *AccountWarehouse) ensurePrincipal(princSpec *principalSpec) (string, error) {
	if princSpec.pType == roleType {
		return wh.ensureRole(princSpec)
	}
	return wh.ensureUser(princSpec)
}

func (wh *AccountWarehouse) ensureIdentityPolicy(spec *policySpec) error {
	if len(spec.rSpecs) == 0 {
		return fmt.Errorf("cannot have policy without any resources")
	}

	switch spec.credSpec.principalSpec.pType {
	case userType:
		return wh.ensureUserPolicy(spec)
	case roleType:
		return wh.ensureRolePolicy(spec)
	default:
		return fmt.Errorf("cannot generate policy for invalid spec with [%v] principal type", spec.credSpec.principalSpec.pType)
	}
}

func convertDamUserIDtoAwsName(endUserID, damSvcUserName string) string {
	parts := strings.SplitN(endUserID, "|", 2)

	sessionName := parts[0] + "@" + damSvcUserName
	maxLen := 64
	if len(sessionName) < 64 {
		maxLen = len(sessionName)
	}
	return sessionName[0:maxLen]
}

func (wh *AccountWarehouse) assumeRole(polSpec *policySpec) (*sts.AssumeRoleOutput, error) {
	params := polSpec.params
	roleARN := polSpec.credSpec.principalSpec.getARN()
	sessionName := convertDamUserIDtoAwsName(params.UserID, wh.svcUserName)

	var sessPolicy *string = nil
	/*
	 Session scope policy restricts permissions granted by identity policy on roles.
	 Read more here: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html#policies_session
	 We need this for resources like redshift dbuser where we want to use a role, but each session only should get
	 access for a particular db user
	*/
	if polSpec.sessionScoped() {
		policyJSON, err := convertToPolicyJSON(polSpec)
		if err != nil {
			return nil, err
		}
		sessPolicy = aws.String(string(policyJSON))
	}

	var aro *sts.AssumeRoleOutput
	f := func() error {
		var err error
		aro, err = wh.apiClient.AssumeRole(&sts.AssumeRoleInput{
			RoleArn:         aws.String(roleARN),
			RoleSessionName: aws.String(sessionName),
			DurationSeconds: toSeconds(params.TTL),
			Policy:          sessPolicy,
		})

		return err
	}

	err := backoff.Retry(f, exponentialBackoff)
	if err != nil {
		return nil, fmt.Errorf("unable to assume role %s: %v", roleARN, err)
	}
	return aro, nil
}

func (wh *AccountWarehouse) ensureLoginProfile(userName string) (string, error) {
	password := uuid.New()
	var call func() error

	_, err := wh.apiClient.GetLoginProfile(&iam.GetLoginProfileInput{UserName: aws.String(userName)})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() == iam.ErrCodeNoSuchEntityException {
			call = func() error {
				_, err := wh.apiClient.CreateLoginProfile(&iam.CreateLoginProfileInput{
					UserName:              aws.String(userName),
					Password:              aws.String(password),
					PasswordResetRequired: aws.Bool(false),
				})

				return err
			}
		} else {
			return "", err
		}
	} else {
		call = func() error {
			_, err := wh.apiClient.UpdateLoginProfile(&iam.UpdateLoginProfileInput{
				UserName:              aws.String(userName),
				Password:              aws.String(password),
				PasswordResetRequired: aws.Bool(false),
			})

			return err
		}
	}

	err = backoff.Retry(call, exponentialBackoff)
	if err != nil {
		return "", fmt.Errorf("unable to create login profile for user %s: %v", userName, err)
	}
	return password, nil
}

func (wh *AccountWarehouse) ensureAccessKey(ctx context.Context, princSpec *principalSpec, svcUserARN string) (*iam.AccessKey, error) {
	// garbage collection call
	makeRoom := princSpec.params.ManagedKeysPerAccount - 1
	keyTTL := timeutil.KeyTTL(princSpec.params.MaxKeyTTL, princSpec.params.ManagedKeysPerAccount)
	userID := princSpec.getID()
	if _, _, err := wh.ManageAccountKeys(ctx, svcUserARN, userID, princSpec.params.TTL, keyTTL, time.Now(), int64(makeRoom)); err != nil {
		return nil, fmt.Errorf("garbage collecting keys: %v", err)
	}

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

func (wh *AccountWarehouse) ensureRolePolicy(spec *policySpec) error {
	spec, err := widenUserScopedResources(*spec)
	if err != nil {
		return fmt.Errorf("unable to generate role policy: %v", err)
	}
	// TODO: handle policy versioning
	policyJSON, err := convertToPolicyJSON(spec)
	if err != nil {
		return fmt.Errorf("error creating AWS policy JSON: %v", err)
	}

	f := func() error { return wh.putRolePolicy(spec, string(policyJSON)) }
	return backoff.Retry(f, exponentialBackoff)
}

func widenUserScopedResources(spec policySpec) (*policySpec, error) {
	rSpecs := make([]*resourceSpec, len(spec.rSpecs))
	for i, rSpec := range spec.rSpecs {
		if rSpec.rType == clusterUserType {
			orig := spec.rSpecs[i]
			widened := *orig
			arnParts := strings.SplitN(orig.arn, ":", 7)
			if len(arnParts) != 7 {
				return nil, fmt.Errorf("given arn is not a cluster DB user: %s", orig.arn)
			}
			dbUserParts := strings.SplitN(arnParts[6], "/", 2)
			if len(dbUserParts) != 2 {
				return nil, fmt.Errorf("given arn is not a cluster DB user: %s", orig.arn)
			}

			widened.arn = fmt.Sprintf(
				"%s:%s:%s:%s:%s:%s:%s/*",
				arnParts[0],
				arnParts[1],
				arnParts[2],
				arnParts[3],
				arnParts[4],
				arnParts[5],
				dbUserParts[0],
			)
			rSpecs[i] = &widened
		} else {
			rSpecs[i] = spec.rSpecs[i]
		}
	}
	spec.rSpecs = rSpecs

	return &spec, nil
}

func convertToPolicyJSON(spec *policySpec) ([]byte, error) {
	resourceARNs := resourceARNToArray(spec.rSpecs)
	policy := &policy{
		Version: "2012-10-17",
		Statement: statement{
			Effect:   "Allow",
			Action:   spec.params.TargetRoles,
			Resource: resourceARNs,
		},
	}

	return json.Marshal(policy)
}

func (wh *AccountWarehouse) putRolePolicy(spec *policySpec, policy string) error {
	_, err := wh.apiClient.PutRolePolicy(&iam.PutRolePolicyInput{
		PolicyName:     aws.String(spec.getID()),
		RoleName:       aws.String(spec.credSpec.principalSpec.getID()),
		PolicyDocument: aws.String(policy),
	})
	if err != nil {
		return fmt.Errorf("unable to create AWS role policy %s: %v", spec.credSpec.principalSpec.getID(), err)
	}
	return nil
}

func (wh *AccountWarehouse) ensureUserPolicy(spec *policySpec) error {
	// TODO: handle policy versioning
	resources := resourceARNToArray(spec.rSpecs)
	policy := &policy{
		Version: "2012-10-17",
		Statement: statement{
			Effect:   "Allow",
			Action:   spec.params.TargetRoles,
			Resource: resources,
			Condition: map[string]interface{}{
				"DateLessThanEquals": map[string]string{
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

func (wh *AccountWarehouse) putUserPolicy(spec *policySpec, policy string) error {
	_, err := wh.apiClient.PutUserPolicy(&iam.PutUserPolicyInput{
		PolicyName:     aws.String(spec.getID()),
		UserName:       aws.String(spec.credSpec.principalSpec.getID()),
		PolicyDocument: aws.String(policy),
	})
	if err != nil {
		return fmt.Errorf("unable to create AWS user policy %s: %v", spec.credSpec.principalSpec.getID(), err)
	}
	return nil
}

// ensures user is created and returns non-empty user ARN if successful
func (wh *AccountWarehouse) ensureUser(spec *principalSpec) (string, error) {
	guo, err := wh.apiClient.GetUser(&iam.GetUserInput{UserName: aws.String(spec.getID())})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() == iam.ErrCodeNoSuchEntityException {
			cuo, err := wh.apiClient.CreateUser(&iam.CreateUserInput{
				UserName: aws.String(spec.getID()),
				Path:     aws.String(spec.path),
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

func (wh *AccountWarehouse) ensureRole(spec *principalSpec) (string, error) {
	gro, err := wh.apiClient.GetRole(&iam.GetRoleInput{RoleName: aws.String(spec.getID())})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() == iam.ErrCodeNoSuchEntityException {
			policy := &policy{
				Version: "2012-10-17",
				Statement: statement{
					Effect: "Allow",
					Principal: map[string]interface{}{
						"AWS": spec.damPrincipalARN,
					},
					Action: []string{"sts:AssumeRole"},
				},
			}
			policyJSON, err := json.Marshal(policy)
			if err != nil {
				return "", fmt.Errorf("error creating AWS policy JSON: %v", err)
			}

			cro, err := wh.apiClient.CreateRole(&iam.CreateRoleInput{
				AssumeRolePolicyDocument: aws.String(string(policyJSON)),
				RoleName:                 aws.String(spec.getID()),
				Path:                     aws.String(spec.path),
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

func extractUserName(userARN string) (string, error) {
	arnParts := strings.Split(userARN, ":")
	if len(arnParts) < 6 {
		return "", fmt.Errorf("argument is not a proper user ARN: %s", userARN)
	}
	pathParts := strings.Split(arnParts[5], "/")

	return pathParts[len(pathParts)-1], nil
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
