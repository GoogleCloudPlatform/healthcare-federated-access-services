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

// Package saw abstracts interacting with certain aspects of Google Cloud
// Platform, such as creating service account keys and access tokens.
package saw

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"path"
	"strings"
	"time"

	glog "github.com/golang/glog" /* copybara-comment */
	"github.com/cenkalti/backoff" /* copybara-comment */
	"golang.org/x/crypto/sha3" /* copybara-comment */
	"google.golang.org/api/bigquery/v2" /* copybara-comment: bigquery */
	"google.golang.org/api/cloudresourcemanager/v1" /* copybara-comment: cloudresourcemanager */
	"google.golang.org/api/googleapi" /* copybara-comment: googleapi */
	"google.golang.org/api/iam/v1" /* copybara-comment: iam */
	"google.golang.org/api/iamcredentials/v1" /* copybara-comment: iamcredentials */
	"google.golang.org/api/option" /* copybara-comment: option */
	gcs "google.golang.org/api/storage/v1" /* copybara-comment: storage */
	grpcbackoff "google3/third_party/golang/grpc/backoff/backoff"
	"google.golang.org/grpc" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds" /* copybara-comment: clouds */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common" /* copybara-comment: common */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/processgc" /* copybara-comment: processgc */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
)

const (
	projectVariable       = "project"
	bucketVariable        = "bucket"
	datasetVariable       = "dataset"
	inheritProject        = "-"
	gcMaxTTL              = 180 * 24 * time.Hour /* 180 days */
	defaultGcFrequency    = 14 * 24 * time.Hour  /* 14 days */
	defaultKeysPerAccount = 10
)

// AccountWarehouse is used to create Google Cloud Platform Service Account
// keys and access tokens associated with a specific identity.
type AccountWarehouse struct {
	iam   *iam.Service
	creds *iamcredentials.Service
	crm   *cloudresourcemanager.Service
	cs    *gcs.Service
	bqDs  *bigquery.DatasetsService
	keyGC *processgc.KeyGC
}

// MustNew builds a *AccountWarehouse. It panics on failure.
func MustNew(ctx context.Context, store storage.Store, opts ...option.ClientOption) *AccountWarehouse {
	// client, err := google.DefaultClient(ctx, "https://www.googleapis.com/auth/cloud-platform")
	// if err != nil {
	// 	glog.Fatalf("google.DefaultClient() failed: %v", err)
	// 	return nil
	// }

	// Use exponential backoff for client calls.
	opts = append(opts, option.WithGRPCDialOption(grpc.WithConnectParams(grpc.ConnectParams{Backoff: grpcbackoff.DefaultConfig})))

	iamc, err := iam.NewService(ctx, opts...)
	if err != nil {
		glog.Fatalf("iam.New() failed: %v", err)
	}

	credsc, err := iamcredentials.NewService(ctx, opts...)
	if err != nil {
		glog.Fatalf("iamcredentials.New() failed: %v", err)
	}

	crmc, err := cloudresourcemanager.NewService(ctx, opts...)
	if err != nil {
		glog.Fatalf(" cloudresourcemanager.New() failed: %v", err)
	}

	gcsc, err := gcs.NewService(ctx, opts...)
	if err != nil {
		glog.Fatalf("gcs.New() failed: %v", err)
	}

	bqc, err := bigquery.NewService(ctx, opts...)
	if err != nil {
		glog.Fatalf("bigquery.New() faild: %v", err)
	}
	bqdsc := bigquery.NewDatasetsService(bqc)

	wh, err := New(store, iamc, credsc, crmc, gcsc, bqdsc, nil)
	if err != nil {
		glog.Fatalf("ServiceAccountWarehouse.New() failed: %v", err)
	}

	// TODO: reverese the dependency.
	// right now  there is a circular dependency between gc and saw.
	// saw is not really dependent on gc, gc is dependent on saw
	// saw just has wrapers for gc functions
	// reversing the creation dependency fixes the issue
	wh.keyGC = processgc.NewKeyGC("gcp_key_gc", wh, store, defaultGcFrequency, defaultKeysPerAccount)

	go wh.Run(ctx)

	return wh
}

// New creates a new AccountWarehouse using the provided client  and options.
func New(store storage.Store, iamc *iam.Service, credsc *iamcredentials.Service, crmc *cloudresourcemanager.Service, gcsc *gcs.Service, bqdsc *bigquery.DatasetsService, kgcp *processgc.KeyGC) (*AccountWarehouse, error) {
	wh := &AccountWarehouse{
		iam:   iamc,
		creds: credsc,
		crm:   crmc,
		cs:    gcsc,
		bqDs:  bqdsc,
		keyGC: kgcp,
	}
	return wh, nil
}

// Run starts background processes of AccountWarehouse.
func (wh *AccountWarehouse) Run(ctx context.Context) {
	// TODO: fix input parameters based on config file.
	wh.keyGC.Run(ctx)
}

// RegisterAccountProject adds a project to the state for workers to process.
func (wh *AccountWarehouse) RegisterAccountProject(project string, tx storage.Tx) error {
	_, err := wh.keyGC.RegisterProject(project, nil, tx)
	return err
}

// UnregisterAccountProject (eventually) removes a project from the active state, and allows cleanup work to be performed.
func (wh *AccountWarehouse) UnregisterAccountProject(project string, tx storage.Tx) error {
	return wh.keyGC.UnregisterProject(project, tx)
}

// UpdateSettings alters resource management settings.
func (wh *AccountWarehouse) UpdateSettings(maxRequestedTTL time.Duration, keysPerAccount int, tx storage.Tx) error {
	return wh.keyGC.UpdateSettings(maxRequestedTTL, keysPerAccount, tx)
}

// MintTokenWithTTL returns an AccountKey or an AccessToken depending on the TTL requested.
func (wh *AccountWarehouse) MintTokenWithTTL(ctx context.Context, id string, ttl, maxTTL time.Duration, numKeys int, params *clouds.ResourceTokenCreationParams) (*clouds.ResourceTokenResult, error) {
	if ttl > maxAccessTokenTTL || httputil.IsJSON(params.TokenFormat) {
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

	mds := make([]*cpb.TokenMetadata, 0, len(k.Keys))
	for _, key := range k.Keys {
		// Use the last part of the key identifier as the GUID.
		parts := strings.Split(key.Name, "/")
		md := &cpb.TokenMetadata{
			Name:     parts[len(parts)-1],
			IssuedAt: key.ValidAfterTime,
			Expires:  key.ValidBeforeTime,
		}
		mds = append(mds, md)
	}
	return mds, nil
}

// DeleteTokens removes tokens belonging to 'id' with given names.
// If 'names' is empty, delete all tokens belonging to 'id'.
func (wh *AccountWarehouse) DeleteTokens(ctx context.Context, project, id string, names []string) error {
	account := wh.GetAccountName(project, id)
	if len(names) == 0 {
		var err error
		names, err = wh.fetchAllNames(ctx, account)
		if err != nil {
			return err
		}
	}

	for _, name := range names {
		if _, err := wh.iam.Projects.ServiceAccounts.Keys.Delete(keyName(account, name)).Context(ctx).Do(); err != nil {
			return fmt.Errorf("deleting token key %q: %v", name, err)
		}
	}
	return nil
}

func (wh *AccountWarehouse) fetchAllNames(ctx context.Context, account string) ([]string, error) {
	k, err := wh.iam.Projects.ServiceAccounts.Keys.List(account).KeyTypes("USER_MANAGED").Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("listing tokens for service keys: %v", err)
	}
	names := make([]string, 0, len(k.Keys))
	for _, key := range k.Keys {
		parts := strings.Split(key.Name, "/")
		name := parts[len(parts)-1]
		names = append(names, name)
	}
	return names, nil
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
	_, _, err = wh.ManageAccountKeys(ctx, params.AccountProject, account, ttl, keyTTL, int64(makeRoom))
	if err != nil {
		return nil, fmt.Errorf("garbage collecting keys: %v", err)
	}
	key, err := wh.iam.Projects.ServiceAccounts.Keys.Create(accountID(inheritProject, account), &iam.CreateServiceAccountKeyRequest{PrivateKeyType: "TYPE_GOOGLE_CREDENTIALS_FILE"}).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("creating key: %v", err)
	}

	if !httputil.IsJSON(params.TokenFormat) {
		return &clouds.ResourceTokenResult{
			Account: account,
			Token:   key.PrivateKeyData,
			Format:  "base64",
		}, nil

	}

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

// ManageAccountKeys maintains or removes keys on a clean-up cycle. Returns: remaining keys for account, removed keys for account, and error.
func (wh *AccountWarehouse) ManageAccountKeys(ctx context.Context, project, account string, ttl, maxKeyTTL time.Duration, keysPerAccount int64) (int, int, error) {
	resp, err := wh.iam.Projects.ServiceAccounts.Keys.List(accountID(inheritProject, account)).KeyTypes("USER_MANAGED").Context(ctx).Do()
	if err != nil {
		return 0, 0, fmt.Errorf("getting key list: %v", err)
	}
	active := 0
	removed := 0
	active = len(resp.Keys)
	rmTime := common.PastTimestamp(maxKeyTTL)
	minTime := common.PastTimestamp(ttl)
	var match *iam.ServiceAccountKey
	for i := 0; i < len(resp.Keys); i++ {
		if resp.Keys[i].ValidAfterTime < rmTime {
			if _, err = wh.iam.Projects.ServiceAccounts.Keys.Delete(resp.Keys[i].Name).Context(ctx).Do(); err != nil {
				return active, removed, fmt.Errorf("deleting key: %v", err)
			}
			resp.Keys = append(resp.Keys[:i], resp.Keys[i+1:]...)
			i--
			active--
			removed++
			continue
		}
		if ttl > 0 && resp.Keys[i].ValidAfterTime > minTime && (match == nil || match.ValidAfterTime < resp.Keys[i].ValidAfterTime) {
			match = resp.Keys[i]
		}
	}
	if match != nil {
		// TODO: remove this matching stuff if it doesn't work (need to make delete an extra key below if can't reuse a key)
		//		return match, active, removed, nil
	}
	for int64(len(resp.Keys)) > keysPerAccount {
		oldIdx := 0
		oldAge := resp.Keys[oldIdx].ValidAfterTime
		for i, key := range resp.Keys {
			if key.ValidAfterTime < oldAge {
				oldIdx = i
				oldAge = key.ValidAfterTime
			}
		}
		if _, err = wh.iam.Projects.ServiceAccounts.Keys.Delete(resp.Keys[oldIdx].Name).Context(ctx).Do(); err != nil {
			return active, removed, fmt.Errorf("deleting key: %v", err)
		}
		resp.Keys = append(resp.Keys[:oldIdx], resp.Keys[oldIdx+1:]...)
		active--
		removed++
	}
	return active, removed, nil
}

// GetAccessToken returns an access token for the service account uniquely
// associated with id.
func (wh *AccountWarehouse) GetAccessToken(ctx context.Context, id string, params *clouds.ResourceTokenCreationParams) (*clouds.ResourceTokenResult, error) {
	account, err := wh.getBackingAccount(ctx, id, params)
	if err != nil {
		return nil, fmt.Errorf("getting backing account: %v", err)
	}

	resp, err := wh.creds.Projects.ServiceAccounts.GenerateAccessToken(accountID(inheritProject, account), &iamcredentials.GenerateAccessTokenRequest{Scope: params.Scopes}).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("generating access token: %v", err)
	}

	return &clouds.ResourceTokenResult{
		Account: account,
		Token:   resp.AccessToken,
		Format:  "base64",
	}, nil
}

// GetServiceAccounts gets the list of service accounts.
func (wh *AccountWarehouse) GetServiceAccounts(ctx context.Context, project string) (<-chan *clouds.Account, error) {

	c := make(chan *clouds.Account)
	go func() {
		defer close(c)

		f := func(page *iam.ListServiceAccountsResponse) error {
			for _, acct := range page.Accounts {
				a := &clouds.Account{
					ID:          acct.Email,
					DisplayName: acct.DisplayName,
					Description: acct.Description,
				}
				select {
				case c <- a:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		}

		resp := wh.iam.Projects.ServiceAccounts.List("projects/" + project)
		if err := resp.Pages(ctx, f); err != nil {
			glog.Errorf("getting service account list: %v", err)
		}
	}()

	return c, nil
}

// RemoveServiceAccount remvoes a service account.
func (wh *AccountWarehouse) RemoveServiceAccount(ctx context.Context, project, email string) error {
	name := accountID(inheritProject, email)
	_, err := wh.iam.Projects.ServiceAccounts.Delete(name).Context(ctx).Do()
	return err
}

// GetAccountName produces a hashed ID and a fully qualified SA name from a 3rd party id.
func (wh *AccountWarehouse) GetAccountName(project, id string) string {
	return accountName(project, hashID(id))
}

func (wh *AccountWarehouse) getBackingAccount(ctx context.Context, id string, params *clouds.ResourceTokenCreationParams) (string, error) {
	service := wh.iam.Projects.ServiceAccounts
	proj := params.AccountProject

	hid := hashID(id)
	name := accountName(proj, hid)
	account, err := service.Get(name).Context(ctx).Do()
	if err == nil {
		// The DisplayName is used as a managed field for auditing and collision detection.
		if account.DisplayName != id {
			return "", fmt.Errorf("user account unavailable for use by user %q", id)
		}
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
				crmPolicyAdd(policy, role, "serviceAccount:"+email)
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
			if params.BillingProject != "" {
				policyCall = policyCall.UserProject(params.BillingProject)
			}
			policy, err := policyCall.Context(ctx).Do()
			if err != nil {
				return convertToPermanentErrorIfApplicable(err, fmt.Errorf("getting IAM policy for bucket %q: %v", bkt, err))
			}
			if len(failedEtag) > 0 && failedEtag == policy.Etag {
				return convertToPermanentErrorIfApplicable(prevErr, fmt.Errorf("setting IAM policy for bucket %q on service account %q: %v", bkt, email, prevErr))
			}
			for _, role := range roles {
				gcsPolicyAdd(policy, role, "serviceAccount:"+email)
			}
			set := wh.cs.Buckets.SetIamPolicy(bkt, policy)
			if params.BillingProject != "" {
				set.UserProject(params.BillingProject)
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

// crmPolicyAdd adds a member to a role in a CRM policy.
func crmPolicyAdd(policy *cloudresourcemanager.Policy, role, member string) {
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
	for _, m := range binding.Members {
		if m == member {
			return
		}
	}
	binding.Members = append(binding.Members, member)
}

// gcsPolicyAdd adds a member to role in a GCS policy.
func gcsPolicyAdd(policy *gcs.Policy, role, member string) {
	var binding *gcs.PolicyBindings
	for _, b := range policy.Bindings {
		if b.Role == role {
			binding = b
			break
		}
	}
	if binding == nil {
		binding = &gcs.PolicyBindings{Role: role}
		policy.Bindings = append(policy.Bindings, binding)
	}

	for _, m := range binding.Members {
		if m == member {
			return
		}
	}
	binding.Members = append(binding.Members, member)
}

func accountName(project, hashID string) string {
	return accountID(project, fmt.Sprintf("%s@%s.iam.gserviceaccount.com", hashID, project))
}

func accountID(project, account string) string {
	return path.Join(projectID(project), "serviceAccounts", account)
}

func hashID(id string) string {
	hash := sha3.Sum224([]byte(id))
	return "i" + hex.EncodeToString(hash[:])[:29]
}

func projectID(project string) string {
	if len(project) == 0 {
		project = "-"
	}
	return path.Join("projects", project)
}

// keyName returns the name of a key.
func keyName(account, name string) string {
	return account + "/keys/" + name
}
