module github.com/GoogleCloudPlatform/healthcare-federated-access-services

go 1.14

require (
	bitbucket.org/creachadair/stringset v0.0.8
	cloud.google.com/go v0.83.0
	cloud.google.com/go/datastore v1.4.0
	cloud.google.com/go/logging v1.4.2
	github.com/alicebob/gopher-json v0.0.0-20200520072559-a9ecdc9d1d3a // indirect
	github.com/alicebob/miniredis v2.5.0+incompatible
	github.com/aws/aws-sdk-go v1.29.15
	github.com/cenkalti/backoff v2.2.0+incompatible
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/go-openapi/strfmt v0.19.3
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/mock v1.5.0
	github.com/golang/protobuf v1.5.2
	github.com/gomodule/redigo v1.8.2
	github.com/google/go-cmp v0.5.6
	github.com/gorilla/mux v1.7.3
	github.com/pborman/uuid v1.2.0
	github.com/pquerna/cachecontrol v0.0.0-20180517163645-1555304b9b35 // indirect
	github.com/yuin/gopher-lua v0.0.0-20200816102855-ee81675732da // indirect
	go.mongodb.org/mongo-driver v1.1.3 // indirect
	golang.org/x/crypto v0.17.0
	golang.org/x/oauth2 v0.0.0-20210514164344-f6687ab2804c
	golang.org/x/text v0.14.0
	google.golang.org/api v0.48.0
	google.golang.org/genproto v0.0.0-20210607140030-00d4fb20b1ae
	google.golang.org/grpc v1.38.0
	google.golang.org/protobuf v1.26.0
	gopkg.in/square/go-jose.v2 v2.5.1
)

replace git.apache.org/thrift.git => github.com/apache/thrift v0.13.0
