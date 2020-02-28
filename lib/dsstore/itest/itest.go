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

// Binary itest runs some code against Datastore.
package main

import (
	"context"
	"flag"

	glog "github.com/golang/glog" /* copybara-comment */
	"cloud.google.com/go/datastore" /* copybara-comment: datastore */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/dsstore" /* copybara-comment: dsstore */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	dpb "github.com/golang/protobuf/ptypes/duration" /* copybara-comment */
)

var (
	fakeProjectID   = flag.String("project_id", "fake-project-id", "")
	fakeServiceName = "fake-service-name"
	fakeConfigPath  = "fake-config-path"
)

func main() {
	ctx := context.Background()
	flag.Parse()

	c, err := datastore.NewClient(ctx, *fakeProjectID)
	if err != nil {
		glog.Exitf("datastore.NewClient(...) failed: %v", err)
	}

	s := dsstore.New(c, *fakeProjectID, fakeServiceName, fakeConfigPath)

	{
		// Write
		tx, err := s.Tx(true)
		if err != nil {
			glog.Exitf("store.Tx(true) failed: %v", err)
		}
		entity := &dpb.Duration{Seconds: 60}
		if err := s.WriteTx("fake-datatype", "fake-realm", "fake-user", "fake-id", storage.LatestRev, entity, nil, tx); err != nil {
			glog.Exitf("store.WriteTx(...) failed: %v", err)
		}
		if err := tx.Finish(); err != nil {
			glog.Exitf("tx.Finish() failed: %v", err)
		}
	}

	{
		// Read to check it is created.
		got := &dpb.Duration{}
		if err := s.Read("fake-datatype", "fake-realm", "fake-user", "fake-id", storage.LatestRev, got); err != nil {
			glog.Exitf("store.Read(...) failed: %v", err)
		}
		want := &dpb.Duration{Seconds: 60}
		if got.GetSeconds() != want.GetSeconds() {
			glog.Exitf("store.Read(...) = %v, want %v", got, want)
		}
	}

	{
		// RMW
		tx, err := s.Tx(true)
		if err != nil {
			glog.Exitf("store.Tx(true) failed: %v", err)
		}
		resp := &dpb.Duration{}
		if err := s.ReadTx("fake-datatype", "fake-realm", "fake-user", "fake-id", storage.LatestRev, resp, tx); err != nil {
			glog.Exitf("store.ReadTx(...) failed: %v", err)
		}

		resp.Seconds = resp.Seconds + 60

		if err := s.WriteTx("fake-datatype", "fake-realm", "fake-user", "fake-id", storage.LatestRev, resp, nil, tx); err != nil {
			glog.Exitf("store.WriteTx(...) failed: %v", err)
		}
		if err := tx.Finish(); err != nil {
			glog.Exitf("tx.Finish() failed: %v", err)
		}
	}

	{
		// Read to check it is updated.
		got := &dpb.Duration{}
		if err := s.Read("fake-datatype", "fake-realm", "fake-user", "fake-id", storage.LatestRev, got); err != nil {
			glog.Exitf("store.Read(...) failed: %v", err)
		}
		want := &dpb.Duration{Seconds: 120}
		if got.GetSeconds() != want.GetSeconds() {
			glog.Exitf("store.Read(...) = %v, want %v", got, want)
		}
	}

	{
		// Delete
		tx, err := s.Tx(true)
		if err != nil {
			glog.Exitf("store.Tx(true) failed: %v", err)
		}
		if err := s.DeleteTx("fake-datatype", "fake-realm", "fake-user", "fake-id", storage.LatestRev, tx); err != nil {
			glog.Exitf("store.DeleteTx(...) failed: %v", err)
		}
		if err := tx.Finish(); err != nil {
			glog.Exitf("tx.Finish() failed: %v", err)
		}
	}

	{
		// Read to check it is deleted.
		if err := s.Read("fake-datatype", "fake-realm", "fake-user", "fake-id", storage.LatestRev, &dpb.Duration{}); status.Code(err) != codes.NotFound {
			glog.Exitf("store.Read(...) = %v, want error with code %v", err, codes.NotFound)
		}
	}

}
