module github.com/GoogleCloudPlatform/healthcare-federated-access-services

go 1.13

require (
	cloud.google.com/go v0.44.3
	cloud.google.com/go/bigquery v1.0.1 // indirect
	cloud.google.com/go/datastore v1.0.0
	github.com/aws/aws-sdk-go v1.25.43
	github.com/cenkalti/backoff v2.1.1+incompatible
	github.com/coreos/go-oidc v2.0.0+incompatible
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/go-openapi/strfmt v0.19.3
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/golang/mock v1.3.1
	github.com/golang/protobuf v1.3.2
	github.com/google/go-cmp v0.3.1
	github.com/gorilla/mux v1.7.3
	github.com/hashicorp/golang-lru v0.5.3 // indirect
	github.com/pborman/uuid v1.2.0
	github.com/pquerna/cachecontrol v0.0.0-20180517163645-1555304b9b35 // indirect
	github.com/stretchr/testify v1.4.0 // indirect
	go.mongodb.org/mongo-driver v1.1.3 // indirect
	golang.org/x/crypto v0.0.0-20190820162420-60c769a6c586
	golang.org/x/exp v0.0.0-20190731235908-ec7cb31e5a56 // indirect
	golang.org/x/lint v0.0.0-20190930215403-16217165b5de // indirect
	golang.org/x/net v0.0.0-20191002035440-2ec189313ef0 // indirect
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
	golang.org/x/sync v0.0.0-20190911185100-cd5d95a43a6e // indirect
	golang.org/x/sys v0.0.0-20191010194322-b09406accb47 // indirect
	golang.org/x/tools v0.0.0-20191115202509-3a792d9c32b2 // indirect
	google.golang.org/api v0.9.0
	google.golang.org/genproto v0.0.0-20190927181202-20e1ac93f88c
	google.golang.org/grpc v1.24.0
	google.golang.org/protobuf v0.0.0-20191114094919-1c31032e00bd
	gopkg.in/square/go-jose.v2 v2.3.1
	gopkg.in/yaml.v2 v2.2.5 // indirect
	honnef.co/go/tools v0.0.1-2019.2.3 // indirect
)

replace git.apache.org/thrift.git => github.com/apache/thrift v0.13.0
