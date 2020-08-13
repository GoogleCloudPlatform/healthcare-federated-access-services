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

	"google.golang.org/grpc/codes" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/aws" /* copybara-comment: aws */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/dam" /* copybara-comment: dam */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakelro" /* copybara-comment: fakelro */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakeoidcissuer" /* copybara-comment: fakeoidcissuer */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */

	glog "github.com/golang/glog" /* copybara-comment */
	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
)

const (
	hydraAdminURL    = "https://admin.hydra.example.com"
	hydraURL         = "https://example.com/"
	hydraURLInternal = "https://hydra.internal.example.com/"
	useHydra         = true
)

func TestCheckIntegrity_FileConfig(t *testing.T) {
	s, cfg := setupFromFile(t)
	glog.Infof("DAMConfig: %v", cfg)
	if err := s.CheckIntegrity(cfg, storage.DefaultRealm, nil).Err(); err != nil {
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
			desc: "bad awsManagedKeysPerIamUser option value (exceeds max)",
			mutation: func(cfg *pb.DamConfig) {
				cfg.Options.AwsManagedKeysPerIamUser = 100000
			},
			want: codes.InvalidArgument,
		},
		{
			desc: "invalid bucket name",
			mutation: func(cfg *pb.DamConfig) {
				cfg.Resources["ga4gh-apis"].Views["gcs_read"].Items[0].Args["bucket"] = "!@@@@"
			},
			want: codes.InvalidArgument,
		},
		{
			desc: "empty bucket name",
			mutation: func(cfg *pb.DamConfig) {
				cfg.Resources["ga4gh-apis"].Views["gcs_read"].Items[0].Args["bucket"] = ""
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
			desc: "all fields of a condition are empty",
			mutation: func(cfg *pb.DamConfig) {
				cfg.Policies["bona_fide"].AnyOf[0].AllOf[0] = &cpb.Condition{}
			},
			want: codes.InvalidArgument,
		},
		{
			desc: "edit built-in policy",
			mutation: func(cfg *pb.DamConfig) {
				cfg.Policies["allowlist"].Ui["label"] = "edited allowlist label that should be rejected"
			},
			want: codes.InvalidArgument,
		},
		{
			desc: "regular (non built-in) policy with UI source label",
			mutation: func(cfg *pb.DamConfig) {
				cfg.Policies["bona_fide"].Ui["source"] = "me"
			},
			want: codes.InvalidArgument,
		},
		{
			desc: "regular (non built-in) policy with UI edit label",
			mutation: func(cfg *pb.DamConfig) {
				cfg.Policies["bona_fide"].Ui["edit"] = "go ahead"
			},
			want: codes.InvalidArgument,
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			s, cfg := setupFromFile(t)
			tc.mutation(cfg)
			if got := s.CheckIntegrity(cfg, storage.DefaultRealm, nil).Code(); got != tc.want {
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
	server, err := fakeoidcissuer.New(hydraURL, &testkeys.PersonaBrokerKey, "dam", "testdata/config", false)
	if err != nil {
		t.Fatalf("fakeoidcissuer.New(%q, _, _) failed: %v", hydraURL, err)
	}
	awsClient := aws.NewMockAPIClient("123456", "dam-user-id")

	for k, v := range dam.BuiltinPolicies {
		p := &pb.Policy{}
		proto.Merge(p, v)
		cfg.Policies[k] = p
	}

	opts := &dam.Options{
		HTTPClient:     server.Client(),
		Domain:         "test.org",
		ServiceName:    "dam",
		DefaultBroker:  "no-broker",
		Store:          store,
		Warehouse:      nil,
		AWSClient:      awsClient,
		UseHydra:       useHydra,
		HydraAdminURL:  hydraAdminURL,
		HydraPublicURL: hydraURL,
		LRO:            fakelro.New(),
	}
	s := dam.NewService(opts)

	return s, cfg
}
