package adapter_test

import (
	"testing"
	"time"

	"golang.org/x/net/context"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/adapter"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/aws"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage"

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1"
)

func TestAwsAdapter(t *testing.T) {
	awsClient := aws.NewMockAPIClient("123456", "dam-user-id")
	secretStore := storage.NewMemoryStorage("dam", "testdata/config")
	secrets := &pb.DamSecrets{}
	if err := secretStore.Read(storage.SecretsDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, secrets); err != nil {
		t.Fatalf("reading secrets file: %v", err)
	}
	adapters := &adapter.ServiceAdapters{
		ByAdapterName: make(map[string]adapter.ServiceAdapter),
		ByServiceName: make(map[string]adapter.ServiceAdapter),
		Descriptors:   make(map[string]*pb.ServiceDescriptor),
	}
	store := storage.NewMemoryStorage("dam", "testdata/config")
	aws, err := adapter.NewAwsAdapter(store, awsClient)
	if err != nil {
		t.Fatalf("new AWS adapter: %v", err)
	}
	adapters.ByAdapterName[adapter.AwsAdapterName] = aws
	for k,v := range aws.Descriptors() {
		adapters.ByServiceName[k] = aws
		adapters.Descriptors[k] = v
	}

	var cfg pb.DamConfig
	cfgStore := storage.NewMemoryStorage("dam", "testdata/config")
	if err := cfgStore.Read(storage.ConfigDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, &cfg); err != nil {
		t.Fatalf("loading config: %v", err)
	}
	//s3 view test
	s3Tmpl := "awsstorage"
	s3St := cfg.ServiceTemplates[s3Tmpl]
	rName := "ga4gh-apis"
	res := cfg.Resources[rName]
	s3Vname := "s3-test"
	s3View := res.Views[s3Vname]
	_, err = aws.CheckConfig(s3Tmpl, s3St, rName, s3Vname, s3View, &cfg, adapters)
	if err != nil {
		t.Errorf("CheckConfig(%q, serviceTemplate, %q, view, cfg, adapters): error %v", s3Tmpl, s3Vname, err)
	}
	s3GrantRole := "viewer"
	identity := &ga4gh.Identity{
		Subject: "marc",
		Issuer:  "https://idp1.org",
	}
	s3SRole, err := adapter.ResolveServiceRole(s3GrantRole, s3View, res, &cfg)
	if err != nil {
		t.Fatalf("ResolveServiceRole(%q, view, res, cfg): error %v", s3GrantRole, err)
	}

	//redshift view test
	redshiftTmpl := "redshift"
	redshiftSt := cfg.ServiceTemplates[redshiftTmpl]
	redshiftVname := "redshift-test"
	redshiftView := res.Views[redshiftVname]
	_, err = aws.CheckConfig(redshiftTmpl, redshiftSt, rName, redshiftVname, redshiftView, &cfg, adapters)
	if err != nil {
		t.Errorf("CheckConfig(%q, serviceTemplate, %q, view, cfg, adapters): error %v", redshiftTmpl, redshiftVname, err)
	}
	redshiftGrantRole := "dbuser"
	redshiftSrole, err := adapter.ResolveServiceRole(redshiftGrantRole, redshiftView, res, &cfg)
	if err != nil {
		t.Fatalf("ResolveServiceRole(%q, view, res, cfg): error %v", redshiftGrantRole, err)
	}

	tests := []struct{
		name   string
		input  *adapter.Action
		fail   bool
	}{
		{
			name: "s3 access token for role",
			input: &adapter.Action{
				ClientID:        "client-id",
				Config:          &cfg,
				GrantRole:       s3GrantRole,
				Identity:        identity,
				MaxTTL:          168 * time.Hour,
				Resource:        res,
				ServiceRole:     s3SRole,
				ServiceTemplate: s3St,
				TTL:             1 * time.Hour,
				View:            s3View,
			},
			fail: false,
		},
		{
			name: "s3 access token for user",
			input: &adapter.Action{
				ClientID:        "client-id",
				Config:          &cfg,
				GrantRole:       s3GrantRole,
				Identity:        identity,
				MaxTTL:          168 * time.Hour,
				Resource:        res,
				ServiceRole:     s3SRole,
				ServiceTemplate: s3St,
				TTL:             13 * time.Hour,
				View:            s3View,
			},
			fail: false,
		},
		{
			name: "s3 too long ttl",
			input: &adapter.Action{
				ClientID:        "client-id",
				Config:          &cfg,
				GrantRole:       s3GrantRole,
				Identity:        identity,
				MaxTTL:          1 * time.Hour,
				Resource:        res,
				ServiceRole:     s3SRole,
				ServiceTemplate: s3St,
				TTL:             169 * time.Hour,
				View:            s3View,
			},
			fail: true,
		},
		{
			name: "redshift access token",
			input: &adapter.Action{
				ClientID:        "client-id",
				Config:          &cfg,
				GrantRole:       redshiftGrantRole,
				Identity:        identity,
				MaxTTL:          168 * time.Hour,
				Resource:        res,
				ServiceRole:     redshiftSrole,
				ServiceTemplate: redshiftSt,
				TTL:             1 * time.Hour,
				View:            redshiftView,
			},
			fail: false,
		},
	}
	for _, test := range tests {
		result, err := aws.MintToken(context.Background(), test.input)
		if test.fail != (err != nil) {
			t.Fatalf("test %q error mismatch: want error %v, got error %v", test.name, test.fail, err)
		}
		if err != nil {
			continue
		}
		if len(result.Credentials) == 0 || len(result.Credentials["account"]) == 0 {
			t.Errorf("test %q credentials mismatch: want non-empty, got empty", test.name)
		}
	}
}
