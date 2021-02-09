module github.com/GoogleCloudPlatform/healthcare-federated-access-services

go 1.14

require (
  bitbucket.org/creachadair/stringset v0.0.8
  cloud.google.com/go v0.76.0
  cloud.google.com/go/datastore v1.4.0
  cloud.google.com/go/logging v1.0.0
  github.com/alicebob/gopher-json v0.0.0-20200520072559-a9ecdc9d1d3a // indirect
  github.com/alicebob/miniredis v2.5.0+incompatible
  github.com/aws/aws-sdk-go v1.29.15
  github.com/cenkalti/backoff v2.2.0+incompatible
  github.com/coreos/go-oidc v2.2.1+incompatible
  github.com/go-openapi/strfmt v0.19.3
  github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
  github.com/golang/mock v1.4.4
  github.com/golang/protobuf v1.4.3
  github.com/gomodule/redigo v1.8.2
  github.com/google/go-cmp v0.5.4
  github.com/gorilla/mux v1.7.3
  github.com/hashicorp/golang-lru v0.5.3 // indirect
  github.com/pborman/uuid v1.2.0
  github.com/pquerna/cachecontrol v0.0.0-20180517163645-1555304b9b35 // indirect
  github.com/yuin/gopher-lua v0.0.0-20200816102855-ee81675732da // indirect
  go.mongodb.org/mongo-driver v1.1.3 // indirect
  golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
  golang.org/x/oauth2 v0.0.0-20210113205817-d3ed898aa8a3
  golang.org/x/text v0.3.5
  google.golang.org/api v0.38.0
  google.golang.org/genproto v0.0.0-20210202153253-cf70463f6119
  google.golang.org/grpc v1.35.0
  google.golang.org/protobuf v1.25.0
  gopkg.in/square/go-jose.v2 v2.5.1
  gopkg.in/yaml.v2 v2.2.5 // indirect
)

replace git.apache.org/thrift.git => github.com/apache/thrift v0.13.0
