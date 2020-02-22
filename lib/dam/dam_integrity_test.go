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

package dam_test

import (
	"testing"

	glog "github.com/golang/glog" /* copybara-comment */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/dam" /* copybara-comment: dam */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
)

const (
	hydraAdminURL = "https://admin.hydra.example.com"
	hydraURL      = "https://example.com/oidc"
	useHydra      = true
)

func TestCheckIntegrity_FileConfig(t *testing.T) {
	s, cfg := setupFromFile(t)
	glog.Infof("DAMConfig: %v", cfg)
	if err := s.CheckIntegrity(cfg).Err(); err != nil {
		t.Errorf("CheckIntegrity(cfg) error: %v", err)
	}
}

func TestCheckIntegrity_BadCfg(t *testing.T) {
	tests := []struct {
		desc     string
		mutation func(*pb.DamConfig)
		want     codes.Code
	}{
		{
			desc: "invalid bucket name",
			mutation: func(cfg *pb.DamConfig) {
				cfg.Resources["ga4gh-apis"].Views["gcs_read"].Items[0].Vars["bucket"] = "!@@@@"
			},
			want: codes.InvalidArgument,
		},
		{
			desc: "empty bucket name",
			mutation: func(cfg *pb.DamConfig) {
				cfg.Resources["ga4gh-apis"].Views["gcs_read"].Items[0].Vars["bucket"] = ""
			},
			want: codes.OK,
		},
		{
			desc: "bad variable in interface",
			mutation: func(cfg *pb.DamConfig) {
				cfg.ServiceTemplates["gcs"].Interfaces["http:test"] = "https://example.com/${bad-variable}"
			},
			want: codes.InvalidArgument,
		},
		{
			desc: "empty condition",
			mutation: func(cfg *pb.DamConfig) {
				assert := cfg.TestPersonas["dr_joe_era_commons"].Passport.Ga4GhAssertions[1].AnyOfConditions[0]
				assert.AllOf = append(assert.AllOf, &cpb.Condition{})
			},
			want: codes.InvalidArgument,
		},
		{
			desc: "resource with no policy",
			mutation: func(cfg *pb.DamConfig) {
				cfg.Resources[""] = &pb.Resource{}
			},
			want: codes.InvalidArgument,
		},
		{
			desc: "all fields of a condition are emptry",
			mutation: func(cfg *pb.DamConfig) {
				cfg.Policies["bona_fide"].AnyOf[0].AllOf[0] = &cpb.Condition{}
			},
			want: codes.InvalidArgument,
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			s, cfg := setupFromFile(t)
			tc.mutation(cfg)
			if got := s.CheckIntegrity(cfg).Code(); got != tc.want {
				t.Errorf("CheckIntegrity(cfg).Code() = %v, want %v", got, tc.want)
			}
		})
	}
}

func setupFromFile(t *testing.T) (*dam.Service, *pb.DamConfig) {
	store := storage.NewMemoryStorage("dam", "testdata/config")
	cfg := &pb.DamConfig{}
	if err := store.Read(storage.ConfigDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, cfg); err != nil {
		t.Fatalf("error reading config: %v", err)
	}

	opts := &dam.Options{
		Domain:         "test.org",
		ServiceName:    "dam",
		DefaultBroker:  "no-broker",
		Store:          store,
		Warehouse:      nil,
		UseHydra:       useHydra,
		HydraAdminURL:  hydraAdminURL,
		HydraPublicURL: hydraURL,
	}
	s := dam.NewService(opts)

	return s, cfg
}
