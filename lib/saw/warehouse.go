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
	"path"
	"sort"
	"strings"
	"time"

	glog "github.com/golang/glog" /* copybara-comment */
	"github.com/cenkalti/backoff" /* copybara-comment */
	iamadmin "cloud.google.com/go/iam/admin/apiv1" /* copybara-comment: admin */
	iamcreds "cloud.google.com/go/iam/credentials/apiv1" /* copybara-comment: credentials */
	"golang.org/x/crypto/sha3" /* copybara-comment */
	"google.golang.org/api/bigquery/v2" /* copybara-comment: bigquery */
	"google.golang.org/api/cloudresourcemanager/v1" /* copybara-comment: cloudresourcemanager */
	"google.golang.org/api/iterator" /* copybara-comment: iterator */
	"google.golang.org/api/option" /* copybara-comment: option */
	gcs "google.golang.org/api/storage/v1" /* copybara-comment: storage */
	grpcbackoff "google.golang.org/grpc/backoff" /* copybara-comment */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds" /* copybara-comment: clouds */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/processgc" /* copybara-comment: processgc */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/timeutil" /* copybara-comment: timeutil */

	iampb "google.golang.org/genproto/googleapis/iam/admin/v1" /* copybara-comment: iam_go_proto */
	iamcredscpb "google.golang.org/genproto/googleapis/iam/credentials/v1" /* copybara-comment: common_go_proto */
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

var userManaged = []iampb.ListServiceAccountKeysRequest_KeyType{iampb.ListServiceAccountKeysRequest_USER_MANAGED}

// GCSPolicy is used to manage IAM policy on GCS buckets.
type GCSPolicy interface {
	Get(ctx context.Context, bkt string, billingProject string) (*gcs.Policy, error)
	Set(ctx context.Context, bkt string, billingProject string, policy *gcs.Policy) error
}

// BQPolicy is used to manage IAM policy on BQ Datasets.
type BQPolicy interface {
	Get(ctx context.Context, project string, dataset string) (*bigquery.Dataset, error)
	Set(ctx context.Context, project string, dataset string, ds *bigquery.Dataset) error
}

// CRMPolicy is used to manage IAM policy on CRM projects.
type CRMPolicy interface {
	Get(ctx context.Context, project string) (*cloudresourcemanager.Policy, error)
	Set(ctx context.Context, project string, policy *cloudresourcemanager.Policy) error
}

// AccountWarehouse is used to create Google Cloud Platform Service Account
// keys and access tokens associated with a specific identity.
type AccountWarehouse struct {
	iam   *iamadmin.IamClient
	creds *iamcreds.IamCredentialsClient
	crm   CRMPolicy
	gcs   GCSPolicy
	bqds  BQPolicy
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

	iamc, err := iamadmin.NewIamClient(ctx, opts...)
	if err != nil {
		glog.Fatalf("iamadmin.NewIamClient() failed: %v", err)
	}

	credsc, err := iamcreds.NewIamCredentialsClient(ctx, opts...)
	if err != nil {
		glog.Fatalf("iamcreds.NewIamCredentialsClient() failed: %v", err)
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

	wh := New(store, iamc, credsc, &CRMPolicyClient{crmc}, &GCSPolicyClient{gcsc}, &BQPolicyClient{bqdsc}, nil)

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
func New(store storage.Store, iamc *iamadmin.IamClient, credsc *iamcreds.IamCredentialsClient, crmc CRMPolicy, gcsc GCSPolicy, bqdsc BQPolicy, kgcp *processgc.KeyGC) *AccountWarehouse {
	wh := &AccountWarehouse{
		iam:   iamc,
		creds: credsc,
		crm:   crmc,
		gcs:   gcsc,
		bqds:  bqdsc,
		keyGC: kgcp,
	}
	return wh
}

// MintTokenWithTTL returns an AccountKey or an AccessToken depending on the TTL requested.
func (wh *AccountWarehouse) MintTokenWithTTL(ctx context.Context, id string, ttl, maxTTL time.Duration, numKeys int, params *clouds.ResourceTokenCreationParams) (*clouds.ResourceTokenResult, error) {
	if ttl > maxAccessTokenTTL || httputils.IsJSON(params.TokenFormat) {
		return wh.GetAccountKey(ctx, id, ttl, maxTTL, numKeys, params)
	}
	return wh.GetAccessToken(ctx, id, ttl, params)
}

// GetTokenMetadata returns an access token based on its key.
func (wh *AccountWarehouse) GetTokenMetadata(ctx context.Context, project, id, keyName string) (*cpb.TokenMetadata, error) {
	account := AccountResourceName(project, EmailID(project, id))
	// A standard Keys.Get does not return ValidAfterTime or ValidBeforeTime
	// so use List and pull the right key out of the list. These lists are small.
	k, err := wh.iam.ListServiceAccountKeys(ctx, &iampb.ListServiceAccountKeysRequest{Name: account, KeyTypes: userManaged})
	if err != nil {
		return nil, fmt.Errorf("getting token service key list: %v", err)
	}
	for _, key := range k.GetKeys() {
		parts := strings.Split(key.Name, "/")
		if keyName == parts[len(parts)-1] {
			return &cpb.TokenMetadata{
				Name:     keyName,
				IssuedAt: timeutil.RFC3339(key.ValidAfterTime),
				Expires:  timeutil.RFC3339(key.ValidBeforeTime),
			}, nil
		}
	}
	return nil, fmt.Errorf("token key %q not found", keyName)
}

// ListTokenMetadata returns a list of outstanding access tokens.
func (wh *AccountWarehouse) ListTokenMetadata(ctx context.Context, project, id string) ([]*cpb.TokenMetadata, error) {
	account := AccountResourceName(project, EmailID(project, id))
	k, err := wh.iam.ListServiceAccountKeys(ctx, &iampb.ListServiceAccountKeysRequest{Name: account, KeyTypes: userManaged})
	if err != nil {
		return nil, fmt.Errorf("list tokens from service keys: %v", err)
	}

	mds := make([]*cpb.TokenMetadata, 0, len(k.Keys))
	for _, key := range k.GetKeys() {
		// Use the last part of the key identifier as the GUID.
		parts := strings.Split(key.Name, "/")
		md := &cpb.TokenMetadata{
			Name:     parts[len(parts)-1],
			IssuedAt: timeutil.RFC3339(key.ValidAfterTime),
			Expires:  timeutil.RFC3339(key.ValidBeforeTime),
		}
		mds = append(mds, md)
	}
	return mds, nil
}

// DeleteTokens removes tokens belonging to 'id' with given names.
// If 'names' is empty, delete all tokens belonging to 'id'.
func (wh *AccountWarehouse) DeleteTokens(ctx context.Context, project, id string, keyNames []string) error {
	account := AccountResourceName(project, EmailID(project, id))
	if len(keyNames) == 0 {
		var err error
		keyNames, err = wh.fetchAllNames(ctx, account)
		if err != nil {
			return err
		}
	}

	for _, name := range keyNames {
		if err := wh.iam.DeleteServiceAccountKey(ctx, &iampb.DeleteServiceAccountKeyRequest{Name: KeyResourceName(project, id, name)}); err != nil {
			return fmt.Errorf("deleting token key %q: %v", name, err)
		}
	}
	return nil
}

func (wh *AccountWarehouse) fetchAllNames(ctx context.Context, account string) ([]string, error) {
	resp, err := wh.iam.ListServiceAccountKeys(ctx, &iampb.ListServiceAccountKeysRequest{Name: account, KeyTypes: userManaged})
	if err != nil {
		return nil, fmt.Errorf("listing tokens for service keys: %v", err)
	}
	names := make([]string, 0, len(resp.Keys))
	for _, key := range resp.GetKeys() {
		parts := strings.Split(key.Name, "/")
		name := parts[len(parts)-1]
		names = append(names, name)
	}
	return names, nil
}

// GetAccountKey returns a service account key associated with id.
func (wh *AccountWarehouse) GetAccountKey(ctx context.Context, id string, ttl, maxTTL time.Duration, numKeys int, params *clouds.ResourceTokenCreationParams) (*clouds.ResourceTokenResult, error) {
	if numKeys == 0 {
		numKeys = defaultKeysPerAccount
	}

	email, err := wh.configureBackingAccount(ctx, id, ttl, params)
	if err != nil {
		return nil, fmt.Errorf("configuring backing account: %v", err)
	}

	// Call Manage to make room for the new key if needed.
	makeRoom := numKeys - 1
	keyTTL := timeutil.KeyTTL(maxTTL, numKeys)
	if _, _, err := wh.ManageAccountKeys(ctx, params.AccountProject, email, ttl, keyTTL, time.Now(), int64(makeRoom)); err != nil {
		return nil, fmt.Errorf("garbage collecting keys: %v", err)
	}

	key, err := wh.iam.CreateServiceAccountKey(ctx, &iampb.CreateServiceAccountKeyRequest{Name: AccountResourceName(params.AccountProject, email), PrivateKeyType: iampb.ServiceAccountPrivateKeyType_TYPE_GOOGLE_CREDENTIALS_FILE})
	if err != nil && status.Code(err) != codes.AlreadyExists {
		return nil, fmt.Errorf("creating key: %v", err)
	}

	if !httputils.IsJSON(params.TokenFormat) {
		return &clouds.ResourceTokenResult{
			Account: email,
			Token:   base64.StdEncoding.EncodeToString(key.PrivateKeyData),
			Format:  "base64",
		}, nil
	}

	return &clouds.ResourceTokenResult{
		Account: email,
		Token:   string(key.PrivateKeyData),
		Format:  params.TokenFormat,
	}, nil
}

// ManageAccountKeys maintains or removes keys on a clean-up cycle.
//   maxTTL is the maximum TTL for keys. Keys which which have expired (key.ValidAfter+maxTTL < now) will be removed.
//   ttl is the TTL provided by user. It is not used currently, will be used later for providing better control later.
//   keysPerAccount is the maximum number of keys allowed per account. If too many keys exists, older keys will be removed.
// Returns:
//   the number of remaining active keys and removed keys for the account.
func (wh *AccountWarehouse) ManageAccountKeys(ctx context.Context, project, email string, ttl, maxTTL time.Duration, now time.Time, keysPerAccount int64) (int, int, error) {
	// TODO: instead of turning duration to string and comparing strings, the string ValidAfterTime should be converted to time and compared using time comparison.
	// A key has expired if key.ValidAfterTime + maxTTL < now, i.e. key.ValidAfterTime < now - maxTTL
	expired := now.Add(-1 * maxTTL).Format(time.RFC3339)

	resp, err := wh.iam.ListServiceAccountKeys(ctx, &iampb.ListServiceAccountKeysRequest{Name: AccountResourceName(project, email), KeyTypes: userManaged})
	if err != nil {
		return 0, 0, fmt.Errorf("getting key list: %v", err)
	}
	all := resp.GetKeys()

	// Removed expired keys.
	var actives []*iampb.ServiceAccountKey
	active := len(all)
	for _, key := range all {
		// Remove old keys.
		if timeutil.RFC3339(key.ValidAfterTime) < expired {
			if err := wh.iam.DeleteServiceAccountKey(ctx, &iampb.DeleteServiceAccountKeyRequest{Name: key.Name}); err != nil {
				return active, len(all) - active, fmt.Errorf("deleting key: %v", err)
			}
			active--
			continue
		}
		actives = append(actives, key)
	}
	if int64(len(actives)) < keysPerAccount {
		return active, len(all) - active, nil
	}

	// Remove earliest expiring extra keys if # of active keys exceeds the max.
	// Sort the keys with decreasing expiry time.
	sort.Slice(actives, func(i, j int) bool {
		return timeutil.RFC3339(actives[i].ValidAfterTime) > timeutil.RFC3339(actives[j].ValidAfterTime)
	})
	for _, key := range actives[keysPerAccount:] {
		if err = wh.iam.DeleteServiceAccountKey(ctx, &iampb.DeleteServiceAccountKeyRequest{Name: key.Name}); err != nil {
			return active, len(all) - active, fmt.Errorf("deleting key: %v", err)
		}
		active--
	}

	return active, len(all) - active, nil
}

// GetAccessToken returns an access token for the service account uniquely
// associated with id.
func (wh *AccountWarehouse) GetAccessToken(ctx context.Context, id string, ttl time.Duration, params *clouds.ResourceTokenCreationParams) (*clouds.ResourceTokenResult, error) {
	email, err := wh.configureBackingAccount(ctx, id, ttl, params)
	if err != nil {
		return nil, fmt.Errorf("getting backing account: %v", err)
	}

	resp, err := wh.creds.GenerateAccessToken(ctx, &iamcredscpb.GenerateAccessTokenRequest{Name: AccountResourceName(inheritProject, email), Scope: params.Scopes})
	if err != nil {
		return nil, fmt.Errorf("generating access token: %v", err)
	}

	return &clouds.ResourceTokenResult{
		Account: email,
		Token:   resp.AccessToken,
		Format:  "base64",
	}, nil
}

// GetServiceAccounts gets the list of service accounts.
func (wh *AccountWarehouse) GetServiceAccounts(ctx context.Context, project string) (<-chan *clouds.Account, error) {

	c := make(chan *clouds.Account)
	go func() {
		defer close(c)

		f := func(acct *iampb.ServiceAccount) error {
			a := &clouds.Account{
				ID:          acct.Email,
				DisplayName: acct.DisplayName,
			}
			select {
			case c <- a:
			case <-ctx.Done():
				return ctx.Err()
			}
			return nil
		}

		it := wh.iam.ListServiceAccounts(ctx, &iampb.ListServiceAccountsRequest{Name: "projects/" + project})
		for {
			accounts, err := it.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				glog.Errorf("getting service account list: %v", err)
				return
			}
			if err := f(accounts); err != nil {
				glog.Errorf("getting service account list: %v", err)
				return
			}
		}
	}()

	return c, nil
}

// RemoveServiceAccount remvoes a service account.
func (wh *AccountWarehouse) RemoveServiceAccount(ctx context.Context, project, id string) error {
	name := AccountResourceName(project, EmailID(project, id))
	return wh.iam.DeleteServiceAccount(ctx, &iampb.DeleteServiceAccountRequest{Name: name})
}

func (wh *AccountWarehouse) configureBackingAccount(ctx context.Context, id string, ttl time.Duration, params *clouds.ResourceTokenCreationParams) (string, error) {
	email, err := wh.getOrCreateBackingAccount(ctx, id, params)
	if err != nil {
		return "", err
	}
	if err := wh.configureRoles(ctx, email, params, ttl); err != nil {
		return "", fmt.Errorf("configuring role for existing account: %v", err)
	}
	return email, nil
}

// getOrCreateBackingAccount returns the accountID (email).
func (wh *AccountWarehouse) getOrCreateBackingAccount(ctx context.Context, id string, params *clouds.ResourceTokenCreationParams) (string, error) {
	proj := params.AccountProject
	hid := HashExternalID(id)
	name := AccountResourceName(proj, EmailID(proj, id))

	account, err := wh.iam.GetServiceAccount(ctx, &iampb.GetServiceAccountRequest{Name: name})
	if err != nil && status.Code(err) != codes.NotFound {
		return "", fmt.Errorf("getting account %q: %v", name, err)
	}
	if err == nil {
		// Account already exists.
		// The DisplayName is used as a managed field for auditing and collision detection.
		if account.DisplayName != id {
			return "", fmt.Errorf("user account unavailable for use by user %q", id)
		}
		return account.Email, nil
	}

	// Account does not exist.
	account, err = wh.iam.CreateServiceAccount(ctx, &iampb.CreateServiceAccountRequest{Name: projectResourceName(proj), AccountId: hid, ServiceAccount: &iampb.ServiceAccount{DisplayName: id}})
	if err != nil {
		return "", fmt.Errorf("creating backing account: %v", err)
	}

	return account.Email, nil
}

type backoffState struct {
	failedEtag string
	prevErr    error
}

// configureRoles applys the changes to policies on IAM, CRM, and GCS for a ResourceTokenCreationParams.
func (wh *AccountWarehouse) configureRoles(ctx context.Context, email string, params *clouds.ResourceTokenCreationParams, ttl time.Duration) error {
	// prMap: map[<projectResourceName>][]<role> stores project-level IAM configurations.
	// bktMap: map[<bucketName>][]<role> stores GCS bucket-level IAM configurations.
	// bqMap: map[<projectResourceName>]map[<datasetID>][]<role> stores BigQuery dataset-level IAM configurations.
	prMap, bktMap, bqMap, err := parseParams(params)
	if err != nil {
		return err
	}

	for project, roles := range prMap {
		f := func() error {
			return applyCRMChange(ctx, wh.crm, email, project, roles, ttl, &backoffState{})
		}
		if err := backoff.Retry(f, exponentialBackoff); err != nil {
			return err
		}
	}

	for bkt, roles := range bktMap {
		f := func() error {
			return applyGCSChange(ctx, wh.gcs, email, bkt, roles, params.BillingProject, ttl, &backoffState{})
		}
		if err := backoff.Retry(f, exponentialBackoff); err != nil {
			return err
		}
	}

	for project, drMap := range bqMap {
		for dataset, roles := range drMap {
			f := func() error { return applyBQDSChange(ctx, wh.bqds, email, project, dataset, roles, &backoffState{}) }
			if err := backoff.Retry(f, exponentialBackoff); err != nil {
				return err
			}
		}
	}
	return nil
}

// parseParams returns the maps for projects, buckets, and BQ datasets.
// map[<projectResourceName>][]<role> stores project-level IAM configurations.
// map[<bucketName>][]<role> stores GCS bucket-level IAM configurations.
// map[<projectResourceName>]map[<datasetID>][]<role> stores BigQuery dataset-level IAM configurations.
func parseParams(params *clouds.ResourceTokenCreationParams) (projects map[string][]string, buckets map[string][]string, bqdatasets map[string]map[string][]string, err error) {
	projects = make(map[string][]string)
	buckets = make(map[string][]string)
	bqdatasets = make(map[string]map[string][]string)

	for _, role := range params.Roles {
		// Roles should be in the format of either
		// projects/{PROJECT-ID}/roles/{ROLE-ID} if it's a custom role defined for
		// a project, or roles/{ROLE-ID} if it's a curated role.
		rparts := strings.Split(role, "/")
		isCustomRole := false
		switch {
		case len(rparts) == 2 || rparts[0] == "roles":
			// non-custom role.
		case len(rparts) == 4 && strings.HasPrefix(role, "projects/${project}/roles/"):
			isCustomRole = true
			role = fmt.Sprintf("roles/%s", rparts[3])
		default:
			return nil, nil, nil, fmt.Errorf(`role %q format not supported: must be "projects/{PROJECT-ID}/roles/{ROLE-ID}" or "roles/{ROLE-ID}"`, role)
		}

		for index, item := range params.Items {
			proj, ok := item[projectVariable]
			if !ok || len(proj) == 0 {
				return nil, nil, nil, fmt.Errorf("item %d variable %q is undefined", index+1, projectVariable)
			}

			resolvedRole := role
			if isCustomRole {
				resolvedRole = fmt.Sprintf("projects/%s/%s", proj, role)
			}

			// If the bucket variable is available, store bucket-level configuration only.
			bkt, ok := item[bucketVariable]
			if ok && len(bkt) > 0 {
				buckets[bkt] = append(buckets[bkt], resolvedRole)
				continue
			}

			// If the dataset variable is available, store dataset-level configurations, and also add a
			// project-level role roles/bigquery.user to give user the permission to run query jobs.
			ds, ok := item[datasetVariable]
			if ok && len(ds) > 0 {
				dr, ok := bqdatasets[proj]
				if !ok {
					dr = make(map[string][]string)
					bqdatasets[proj] = dr
				}
				dr[ds] = append(dr[ds], resolvedRole)
				resolvedRole = "roles/bigquery.user"
			}

			// Otherwise, store project-level configuration.
			projects[proj] = append(projects[proj], resolvedRole)
		}
	}
	return
}

// HashExternalID hashes an external ID.
func HashExternalID(id string) string {
	hash := sha3.Sum224([]byte(id))
	return "i" + hex.EncodeToString(hash[:])[:29]
}

// EmailID returns the resource ID (email) of a given external id.
// "HASH(ID)@PROJECT.iam.gserviceaccount.com"
func EmailID(project, id string) string {
	return fmt.Sprintf("%s@%s.iam.gserviceaccount.com", HashExternalID(id), project)
}

// projectResourceName returns name of a project given its project ID.
func projectResourceName(projectID string) string {
	if projectID == "" {
		projectID = "-"
	}
	return path.Join("projects", projectID)
}

// AccountResourceName returns name of a service account given its project ID name and account ID.
func AccountResourceName(projectID, accountID string) string {
	return path.Join(projectResourceName(projectID), "serviceAccounts", accountID)
}

// KeyResourceName returns name of a service account key given its project ID and service accounts ID and key ID.
func KeyResourceName(projectID, accountID, keyID string) string {
	account := AccountResourceName(projectID, EmailID(projectID, accountID))
	return path.Join(account, "keys", keyID)
}
