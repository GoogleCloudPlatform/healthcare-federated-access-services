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

package saw

import (
	"context"
	"fmt"

	"google.golang.org/api/bigquery/v2" /* copybara-comment: bigquery */

	glog "github.com/golang/glog" /* copybara-comment */
)

// BQPolicyClient is used to manage IAM policy on BQ Datasets.
type BQPolicyClient struct {
	bqdsc *bigquery.DatasetsService
}

func (c *BQPolicyClient) Get(ctx context.Context, project string, dataset string) (*bigquery.Dataset, error) {
	return c.bqdsc.Get(project, dataset).Context(ctx).Do()
}

func (c *BQPolicyClient) Set(ctx context.Context, project string, dataset string, ds *bigquery.Dataset) error {
	_, err := c.bqdsc.Patch(project, dataset, &bigquery.Dataset{Access: ds.Access, Etag: ds.Etag}).Context(ctx).Do()
	return err
}

func applyBQDSChange(ctx context.Context, bqdsc BQPolicy, email string, project string, dataset string, roles []string, state *backoffState) error {
	ds, err := bqdsc.Get(ctx, project, dataset)
	if err != nil {
		return convertToPermanentErrorIfApplicable(err, fmt.Errorf("getting BigQuery dataset %q of project %q: %v", dataset, project, err))
	}
	if len(state.failedEtag) > 0 && state.failedEtag == ds.Etag {
		return convertToPermanentErrorIfApplicable(state.prevErr, fmt.Errorf("updating BigQuery dataset %q of project %q: %v", dataset, project, state.prevErr))
	}

	for _, role := range roles {
		bqdsAddPolicy(ds, role, email)
	}

	// Only patch the updated access list.
	if err := bqdsc.Set(ctx, project, dataset, ds); err != nil {
		state.failedEtag = ds.Etag
		state.prevErr = err
		glog.Errorf("set iam for bq failed: etag=%s err=%v", ds.Etag, err)
		return err
	}
	return nil
}

func bqdsAddPolicy(ds *bigquery.Dataset, role string, email string) {
	da := &bigquery.DatasetAccess{
		UserByEmail: email,
		Role:        role,
	}
	for _, a := range ds.Access {
		if a == da {
			return
		}
	}
	ds.Access = append(ds.Access, da)
}
