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
package gcp

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage"

	"github.com/cenkalti/backoff"
	"golang.org/x/crypto/sha3"

	// Using a deprecated library because the new version doesn't support setting IAM roles in
	// BigQuery datasets yet.
	"google.golang.org/api/bigquery/v2"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/iamcredentials/v1"
	cloudstorage "google.golang.org/api/storage/v1"

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1"
)

const (
	projectVariable       = "project"
	bucketVariable        = "bucket"
	datasetVariable       = "dataset"
	inheritProject        = "-"
	gcMaxTTL              = 180 * 24 * 60 * 60 /* 180 days */
	defaultKeysPerAccount = 10

	backoffInitialInterval     = 1 * time.Second
	backoffRandomizationFactor = 0.5
	backoffMultiplier          = 1.5
	backoffMaxInterval         = 3 * time.Second
	backoffMaxElapsedTime      = 10 * time.Second
)

var (
	maxAccessTokenTTL  = 1 * time.Hour
	exponentialBackoff = &backoff.ExponentialBackOff{
		InitialInterval:     backoffInitialInterval,
		RandomizationFactor: backoffRandomizationFactor,
		Multiplier:          backoffMultiplier,
		MaxInterval:         backoffMaxInterval,
		MaxElapsedTime:      backoffMaxElapsedTime,
		Clock:               backoff.SystemClock,
	}
)

// AccountWarehouse is used to create Google Cloud Platform Service Account
// keys and access tokens associated with a specific identity.
type AccountWarehouse struct {
	iam   *iam.Service
	creds *iamcredentials.Service
	crm   *cloudresourcemanager.Service
	cs    *cloudstorage.Service
	bqDs  *bigquery.DatasetsService
	keyGC *KeyGarbageCollector
}

// NewAccountWarehouse creates a new AccountWarehouse using the provided client
// and options.
func NewAccountWarehouse(client *http.Client, store storage.Store) (*AccountWarehouse, error) {
	iamSvc, err := iam.New(client)
	if err != nil {
		return nil, fmt.Errorf("creating IAM client: %v", err)
	}

	creds, err := iamcredentials.New(client)
	if err != nil {
		return nil, fmt.Errorf("creating IAM credentials client: %v", err)
	}

	crm, err := cloudresourcemanager.New(client)
	if err != nil {
		return nil, fmt.Errorf("creating cloud resource manager client: %v", err)
	}

	cs, err := cloudstorage.New(client)
	if err != nil {
		return nil, fmt.Errorf("creating cloud storage client: %v", err)
	}

	bq, err := bigquery.New(client)
	if err != nil {
		return nil, fmt.Errorf("creating BigQuery client: %v", err)
	}
	bqDs := bigquery.NewDatasetsService(bq)

	wh := &AccountWarehouse{
		iam:   iamSvc,
		creds: creds,
		crm:   crm,
		cs:    cs,
		bqDs:  bqDs,
	}

	gc, err := NewKeyGarbageCollector(store, wh)
	if err != nil {
		return nil, fmt.Errorf("creating key garbage collector: %v", err)
	}
	wh.keyGC = gc
	return wh, nil
}

func (wh *AccountWarehouse) RegisterAccountProject(realm, project string, maxRequestedTTL int, keysPerAccount int) error {
	if keysPerAccount == 0 {
		keysPerAccount = defaultKeysPerAccount
	}
	return wh.keyGC.RegisterProject(realm, project, time.Second*time.Duration(maxRequestedTTL), keysPerAccount)
}

// MintTokenWithTTL returns an AccountKey or an AccessToken depending on the TTL requested.
func (wh *AccountWarehouse) MintTokenWithTTL(ctx context.Context, id string, ttl, maxTTL time.Duration, numKeys int, params *clouds.ResourceTokenCreationParams) (*clouds.ResourceTokenResult, error) {
	if ttl > maxAccessTokenTTL || common.IsJSON(params.TokenFormat) {
		return wh.GetAccountKey(ctx, id, ttl, maxTTL, numKeys, params)
	}
	return wh.GetAccessToken(ctx, id, params)
}

// GetTokenMetadata returns an access token based on its name.
func (wh *AccountWarehouse) GetTokenMetadata(ctx context.Context, project, id, name string) (*cpb.TokenMetadata, error) {
	account := wh.GetAccountName(project, id)
	// A standard Keys.Get does not return ValidAfterTime or ValidBeforeTime
	// so use List and pull the right key out of the list. These lists are small.
	k, err := wh.iam.Projects.ServiceAccounts.Keys.List(account).KeyTypes("USER_MANAGED").Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("getting token service key list: %v", err)
	}
	for _, key := range k.Keys {
		parts := strings.Split(key.Name, "/")
		if name == parts[len(parts)-1] {
			return &cpb.TokenMetadata{
				Name:     name,
				IssuedAt: key.ValidAfterTime,
				Expires:  key.ValidBeforeTime,
			}, nil
		}
	}
	return nil, fmt.Errorf("token key %q not found", name)
}

// ListTokenMetadata returns a list of outstanding access tokens.
func (wh *AccountWarehouse) ListTokenMetadata(ctx context.Context, project, id string) ([]*cpb.TokenMetadata, error) {
	account := wh.GetAccountName(project, id)
	k, err := wh.iam.Projects.ServiceAccounts.Keys.List(account).KeyTypes("USER_MANAGED").Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("list tokens from service keys: %v", err)
	}
	out := make([]*cpb.TokenMetadata, len(k.Keys))
	for i, key := range k.Keys {
		// Use the last part of the key identifier as the GUID.
		parts := strings.Split(key.Name, "/")
		out[i] = &cpb.TokenMetadata{
			Name:     parts[len(parts)-1],
			IssuedAt: key.ValidAfterTime,
			Expires:  key.ValidBeforeTime,
		}
	}

	return out, nil
}

// DeleteTokens removes tokens belonging to 'id' with given names.
// If 'names' is empty, delete all tokens belonging to 'id'.
func (wh *AccountWarehouse) DeleteTokens(ctx context.Context, project, id string, names []string) error {
	account := wh.GetAccountName(project, id)
	if len(names) == 0 {
		k, err := wh.iam.Projects.ServiceAccounts.Keys.List(account).KeyTypes("USER_MANAGED").Context(ctx).Do()
		if err != nil {
			return fmt.Errorf("listing tokens for service keys: %v", err)
		}
		names = make([]string, len(k.Keys))
		for i, key := range k.Keys {
			parts := strings.Split(key.Name, "/")
			names[i] = parts[len(parts)-1]
		}
	}
	keyPrefix := account + "/keys/"
	for _, name := range names {
		fullKeyName := keyPrefix + name
		if _, err := wh.iam.Projects.ServiceAccounts.Keys.Delete(fullKeyName).Context(ctx).Do(); err != nil {
			return fmt.Errorf("deleting token key %q: %v", name, err)
		}
	}
	return nil
}

// GetAccountKey returns a service account key associated with id.
func (wh *AccountWarehouse) GetAccountKey(ctx context.Context, id string, ttl, maxTTL time.Duration, numKeys int, params *clouds.ResourceTokenCreationParams) (*clouds.ResourceTokenResult, error) {
	account, err := wh.getBackingAccount(ctx, id, params)
	if err != nil {
		return nil, fmt.Errorf("getting backing account: %v", err)
	}

	if numKeys == 0 {
		numKeys = defaultKeysPerAccount
	}
	makeRoom := numKeys - 1
	keyTTL := common.KeyTTL(maxTTL, numKeys)
	_, _, _, err = wh.ManageAccountKeys(ctx, params.AccountProject, account, ttl, keyTTL, makeRoom)
	if err != nil {
		return nil, fmt.Errorf("garbage collecting keys: %v", err)
	}
	key, err := wh.iam.Projects.ServiceAccounts.Keys.Create(accountID(inheritProject, account), &iam.CreateServiceAccountKeyRequest{
		PrivateKeyType: "TYPE_GOOGLE_CREDENTIALS_FILE",
	}).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("creating key: %v", err)
	}

	if common.IsJSON(params.TokenFormat) {
		bytes, err := base64.StdEncoding.DecodeString(key.PrivateKeyData)
		if err != nil {
			return nil, fmt.Errorf("decoding key: %v", err)
		}
		return &clouds.ResourceTokenResult{
			Account: account,
			Token:   string(bytes),
			Format:  params.TokenFormat,
		}, nil
	}

	return &clouds.ResourceTokenResult{
		Account: account,
		Token:   key.PrivateKeyData,
		Format:  "base64",
	}, nil
}

func (wh *AccountWarehouse) ManageAccountKeys(ctx context.Context, project, account string, ttl, maxKeyTTL time.Duration, keysPerAccount int) (*iam.ServiceAccountKey, int, int, error) {
	active := 0
	removed := 0
	k, err := wh.iam.Projects.ServiceAccounts.Keys.List(accountID(inheritProject, account)).KeyTypes("USER_MANAGED").Context(ctx).Do()
	if err != nil {
		return nil, active, removed, fmt.Errorf("getting key list: %v", err)
	}
	active = len(k.Keys)
	rmTime := common.PastTimestamp(maxKeyTTL)
	minTime := common.PastTimestamp(ttl)
	var match *iam.ServiceAccountKey
	for i := 0; i < len(k.Keys); i++ {
		if k.Keys[i].ValidAfterTime < rmTime {
			if _, err = wh.iam.Projects.ServiceAccounts.Keys.Delete(k.Keys[i].Name).Context(ctx).Do(); err != nil {
				return nil, active, removed, fmt.Errorf("deleting key: %v", err)
			}
			k.Keys = append(k.Keys[:i], k.Keys[i+1:]...)
			i--
			active--
			removed++
		} else if ttl > 0 && k.Keys[i].ValidAfterTime > minTime && (match == nil || match.ValidAfterTime < k.Keys[i].ValidAfterTime) {
			match = k.Keys[i]
		}
	}
	if match != nil {
		// TODO: remove this matching stuff if it doesn't work (need to make delete an extra key below if can't reuse a key)
		//		return match, active, removed, nil
	}
	for len(k.Keys) > keysPerAccount {
		oldIdx := 0
		oldAge := k.Keys[oldIdx].ValidAfterTime
		for i, key := range k.Keys {
			if key.ValidAfterTime < oldAge {
				oldIdx = i
				oldAge = key.ValidAfterTime
			}
		}
		if _, err = wh.iam.Projects.ServiceAccounts.Keys.Delete(k.Keys[oldIdx].Name).Context(ctx).Do(); err != nil {
			return nil, active, removed, fmt.Errorf("deleting key: %v", err)
		}
		k.Keys = append(k.Keys[:oldIdx], k.Keys[oldIdx+1:]...)
		active--
		removed++
	}
	return nil, active, removed, nil
}

// GetAccessToken returns an access token for the service account uniquely
// associated with id.
func (wh *AccountWarehouse) GetAccessToken(ctx context.Context, id string, params *clouds.ResourceTokenCreationParams) (*clouds.ResourceTokenResult, error) {
	account, err := wh.getBackingAccount(ctx, id, params)
	if err != nil {
		return nil, fmt.Errorf("getting backing account: %v", err)
	}

	response, err := wh.creds.Projects.ServiceAccounts.GenerateAccessToken(accountID(inheritProject, account), &iamcredentials.GenerateAccessTokenRequest{
		Scope: params.Scopes,
	}).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("generating access token: %v", err)
	}

	return &clouds.ResourceTokenResult{
		Account: account,
		Token:   response.AccessToken,
		Format:  "base64",
	}, nil
}

func (wh *AccountWarehouse) GetServiceAccounts(ctx context.Context, project string, callback func(sa *iam.ServiceAccount) bool) error {
	req := wh.iam.Projects.ServiceAccounts.List("projects/" + project)
	if err := req.Pages(ctx, func(page *iam.ListServiceAccountsResponse) error {
		for _, serviceAccount := range page.Accounts {
			if callback(serviceAccount) == false {
				break
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("getting service account list: %v", err)
	}
	return nil
}

func (wh *AccountWarehouse) RemoveServiceAccount(ctx context.Context, project, email string) error {
	service := wh.iam.Projects.ServiceAccounts
	name := accountID(inheritProject, email)
	return exponentialBackoffRetry(func() error {
		_, err := service.Delete(name).Context(ctx).Do()
		return err
	})
}

// GetAccountName produces a hashed ID and a fully qualified SA name from a 3rd party id.
func (wh *AccountWarehouse) GetAccountName(project, id string) string {
	hid := hashID(id)
	return accountName(project, hid)
}

func accountName(project, hashID string) string {
	return accountID(project, fmt.Sprintf("%s@%s.iam.gserviceaccount.com", hashID, project))
}

func (wh *AccountWarehouse) getBackingAccount(ctx context.Context, id string, params *clouds.ResourceTokenCreationParams) (string, error) {
	service := wh.iam.Projects.ServiceAccounts
	proj := params.AccountProject

	hid := hashID(id)
	name := accountName(proj, hid)
	account, err := service.Get(name).Context(ctx).Do()
	if err == nil {
		// TODO: verify there are no user_id->SA_account collisions.
		if err := wh.configureRoles(ctx, account.Email, params); err != nil {
			return "", fmt.Errorf("configuring role for existing account: %v", err)
		}
		return account.Email, nil
	}
	if gerr, ok := err.(*googleapi.Error); !ok || gerr.Code != http.StatusNotFound {
		return "", fmt.Errorf("getting account %q: %v", name, err)
	}

	account, err = service.Create(projectID(proj), &iam.CreateServiceAccountRequest{
		AccountId: hid,
		ServiceAccount: &iam.ServiceAccount{
			DisplayName: id,
		},
	}).Context(ctx).Do()
	if err != nil {
		return "", fmt.Errorf("creating backing account: %v", err)
	}
	if err := wh.configureRoles(ctx, account.Email, params); err != nil {
		return "", fmt.Errorf("configuring role for new account: %v", err)
	}
	return account.Email, nil
}

func (wh *AccountWarehouse) configureRoles(ctx context.Context, email string, params *clouds.ResourceTokenCreationParams) error {
	// map[<projectID>][]<role> stores project-level IAM configurations.
	prMap := make(map[string][]string)
	// map[<bucketName>][]<role> stores GCS bucket-level IAM configurations.
	bktMap := make(map[string][]string)
	// map[<projectID>]map[<datasetID>][]<role> stores BigQuery dataset-level IAM configurations.
	bqMap := make(map[string]map[string][]string)

	for _, role := range params.Roles {
		// Roles should be in the format of either
		// projects/{PROJECT-ID}/roles/{ROLE-ID} if it's a custom role defined for
		// a project, or roles/{ROLE-ID} if it's a curated role.
		rparts := strings.Split(role, "/")
		isCustomRole := false
		if len(rparts) == 4 && strings.HasPrefix(role, "projects/${project}/roles/") {
			isCustomRole = true
			role = fmt.Sprintf("roles/%s", rparts[3])
		} else if len(rparts) != 2 || rparts[0] != "roles" {
			return fmt.Errorf(`role %q format not supported: must be "projects/{PROJECT-ID}/roles/{ROLE-ID}" or "roles/{ROLE-ID}"`, role)
		}
		for index, item := range params.Items {
			proj, ok := item[projectVariable]
			if !ok || len(proj) == 0 {
				return fmt.Errorf("item %d variable %q is undefined", index+1, projectVariable)
			}
			resolvedRole := role
			if isCustomRole {
				resolvedRole = fmt.Sprintf("projects/%s/%s", proj, role)
			}
			// If the bucket variable is available, store bucket-level configuration only.
			bkt, ok := item[bucketVariable]
			if ok && len(bkt) > 0 {
				bktMap[bkt] = append(bktMap[bkt], resolvedRole)
				continue
			}
			// If the dataset variable is available, store dataset-level configurations, and also add a
			// project-level role roles/bigquery.user to give user the permission to run query jobs.
			ds, ok := item[datasetVariable]
			if ok && len(ds) > 0 {
				dr, ok := bqMap[proj]
				if !ok {
					dr = make(map[string][]string)
					bqMap[proj] = dr
				}
				dr[ds] = append(dr[ds], resolvedRole)
				resolvedRole = "roles/bigquery.user"
			}
			// Otherwise, store project-level configuration.
			prMap[proj] = append(prMap[proj], resolvedRole)
		}
	}

	for project, roles := range prMap {
		var failedEtag string
		var prevErr error
		if err := backoff.Retry(func() error {
			policy, err := wh.crm.Projects.GetIamPolicy(project, &cloudresourcemanager.GetIamPolicyRequest{}).Context(ctx).Do()
			if err != nil {
				return convertToPermanentErrorIfApplicable(err, fmt.Errorf("getting IAM policy for project %q: %v", project, err))
			}
			// If the etag of the policy that previously failed to set still matches the etag of the
			// the current state of the policy, then the previous error returned by SetIamPolicy is not
			// related to etag and is hence a permanent error. Note that having matching etags doesn't
			// necessarily mean that the previous error is an etag error since the policy might have
			// changed between retry calls.
			if len(failedEtag) > 0 && failedEtag == policy.Etag {
				return convertToPermanentErrorIfApplicable(prevErr, fmt.Errorf("setting IAM policy for project %q on service account %q: %v", project, email, prevErr))
			}
			for _, role := range roles {
				wh.configureProjectRole(policy, role, email)
			}
			_, err = wh.crm.Projects.SetIamPolicy(project, &cloudresourcemanager.SetIamPolicyRequest{Policy: policy}).Context(ctx).Do()
			if err != nil {
				failedEtag = policy.Etag
				prevErr = err
			}
			return err
		}, exponentialBackoff); err != nil {
			return err
		}
	}

	for bkt, roles := range bktMap {
		var failedEtag string
		var prevErr error
		if err := backoff.Retry(func() error {
			policyCall := wh.cs.Buckets.GetIamPolicy(bkt)
			if params.UserProject != "" {
				policyCall = policyCall.UserProject(params.UserProject)
			}
			policy, err := policyCall.Context(ctx).Do()
			if err != nil {
				return convertToPermanentErrorIfApplicable(err, fmt.Errorf("getting IAM policy for bucket %q: %v", bkt, err))
			}
			if len(failedEtag) > 0 && failedEtag == policy.Etag {
				return convertToPermanentErrorIfApplicable(prevErr, fmt.Errorf("setting IAM policy for bucket %q on service account %q: %v", bkt, email, prevErr))
			}
			for _, role := range roles {
				wh.configureBucketRole(policy, role, email)
			}
			set := wh.cs.Buckets.SetIamPolicy(bkt, policy)
			if params.UserProject != "" {
				set.UserProject(params.UserProject)
			}
			_, err = set.Context(ctx).Do()
			if err != nil {
				failedEtag = policy.Etag
				prevErr = err
			}
			return err
		}, exponentialBackoff); err != nil {
			return err
		}
	}

	for project, drMap := range bqMap {
		for dataset, roles := range drMap {
			var failedEtag string
			var prevErr error
			if err := backoff.Retry(func() error {
				ds, err := wh.bqDs.Get(project, dataset).Context(ctx).Do()
				if err != nil {
					return convertToPermanentErrorIfApplicable(err, fmt.Errorf("getting BigQuery dataset %q of project %q: %v", dataset, project, err))
				}
				if len(failedEtag) > 0 && failedEtag == ds.Etag {
					return convertToPermanentErrorIfApplicable(prevErr, fmt.Errorf("updating BigQuery dataset %q of project %q: %v", dataset, project, prevErr))
				}
				for _, role := range roles {
					da := &bigquery.DatasetAccess{
						UserByEmail: email,
						Role:        role,
					}
					found := false
					for _, a := range ds.Access {
						if a == da {
							found = true
							break
						}
					}
					if !found {
						ds.Access = append(ds.Access, da)
					}
				}
				// Only patch the updated access list.
				_, err = wh.bqDs.Patch(project, dataset, &bigquery.Dataset{Access: ds.Access}).Context(ctx).Do()
				if err != nil {
					failedEtag = ds.Etag
					prevErr = err
				}
				return err
			}, exponentialBackoff); err != nil {
				return err
			}
		}
	}
	return nil
}

// configureProjectRole adds an IAM role for an email in the project policy.
func (wh *AccountWarehouse) configureProjectRole(policy *cloudresourcemanager.Policy, role, email string) {
	// Retrieve the existing binding for the given role if available, otherwise
	// create one.
	var binding *cloudresourcemanager.Binding
	for _, b := range policy.Bindings {
		if b.Role == role {
			binding = b
			break
		}
	}
	if binding == nil {
		binding = &cloudresourcemanager.Binding{
			Role:    role,
			Members: []string{},
		}
		policy.Bindings = append(policy.Bindings, binding)
	}

	// Add the given email to this binding's member list.
	qualifiedName := "serviceAccount:" + email
	for _, member := range binding.Members {
		if member == qualifiedName {
			return
		}
	}
	binding.Members = append(binding.Members, qualifiedName)
}

// configureBucketRole adds an IAM role for an email in the GCS bucket policy.
func (wh *AccountWarehouse) configureBucketRole(policy *cloudstorage.Policy, role, email string) {
	var binding *cloudstorage.PolicyBindings
	for _, b := range policy.Bindings {
		if b.Role == role {
			binding = b
			break
		}
	}
	if binding == nil {
		binding = &cloudstorage.PolicyBindings{
			Role:    role,
			Members: []string{},
		}
		policy.Bindings = append(policy.Bindings, binding)
	}
	qualifiedName := "serviceAccount:" + email
	for _, member := range binding.Members {
		if member == qualifiedName {
			return
		}
	}
	binding.Members = append(binding.Members, qualifiedName)
}

func hashID(id string) string {
	hash := sha3.Sum224([]byte(id))
	return "i" + hex.EncodeToString(hash[:])[:29]
}

func accountID(project, account string) string {
	return path.Join(projectID(project), "serviceAccounts", account)
}

func projectID(project string) string {
	if len(project) == 0 {
		project = "-"
	}
	return path.Join("projects", project)
}

func convertToPermanentErrorIfApplicable(err error, formattedErr error) error {
	if googleErr, ok := err.(*googleapi.Error); ok {
		// This logic follows the guidance at
		// https://cloud.google.com/apis/design/errors#error_retries.
		if googleErr.Code == 500 || googleErr.Code == 503 {
			return formattedErr
		}
	}
	// TODO: Extend this function's logic if other types of errors need
	// to be classified as permanent errors vs. retryable errors.
	return backoff.Permanent(formattedErr)
}

func exponentialBackoffRetry(o backoff.Operation) error {
	return backoff.Retry(func() error {
		err := o()
		return convertToPermanentErrorIfApplicable(err, err)
	}, exponentialBackoff)
}
