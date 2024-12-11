module github.com/GoogleCloudPlatform/healthcare-federated-access-services

go 1.21

require (
	bitbucket.org/creachadair/stringset v0.0.14
	cloud.google.com/go/datastore v1.15.0
	cloud.google.com/go/iam v1.1.7
	cloud.google.com/go/kms v1.15.8
	cloud.google.com/go/logging v1.9.0
	cloud.google.com/go/secretmanager v1.12.0
	github.com/alicebob/miniredis v2.5.0+incompatible
	github.com/aws/aws-sdk-go v1.51.24
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/go-jose/go-jose/v3 v3.0.3
	github.com/go-openapi/strfmt v0.23.0
	github.com/golang/glog v1.2.1
	github.com/golang/mock v1.6.0
	github.com/golang/protobuf v1.5.4
	github.com/gomodule/redigo v1.9.2
	github.com/google/go-cmp v0.6.0
	github.com/gorilla/mux v1.8.1
	github.com/pborman/uuid v1.2.1
	golang.org/x/crypto v0.31.0
	golang.org/x/oauth2 v0.19.0
	golang.org/x/text v0.21.0
	google.golang.org/api v0.174.0
	google.golang.org/genproto v0.0.0-20240415180920-8c6c420018be
	google.golang.org/genproto/googleapis/api v0.0.0-20240415180920-8c6c420018be
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240415180920-8c6c420018be
	google.golang.org/grpc v1.63.2
	google.golang.org/protobuf v1.33.0
)

require (
	cloud.google.com/go v0.112.2 // indirect
	cloud.google.com/go/auth v0.2.1 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.1 // indirect
	cloud.google.com/go/compute/metadata v0.3.0 // indirect
	cloud.google.com/go/longrunning v0.5.6 // indirect
	github.com/alicebob/gopher-json v0.0.0-20230218143504-906a9b012302 // indirect
	github.com/asaskevich/govalidator v0.0.0-20230301143203-a9d515a09cc2 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/logr v1.4.1 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-openapi/errors v0.22.0 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/google/s2a-go v0.1.7 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.2 // indirect
	github.com/googleapis/gax-go/v2 v2.12.3 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/oklog/ulid v1.3.1 // indirect
	github.com/pquerna/cachecontrol v0.2.0 // indirect
	github.com/yuin/gopher-lua v1.1.1 // indirect
	go.mongodb.org/mongo-driver v1.15.0 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.50.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.50.0 // indirect
	go.opentelemetry.io/otel v1.25.0 // indirect
	go.opentelemetry.io/otel/metric v1.25.0 // indirect
	go.opentelemetry.io/otel/trace v1.25.0 // indirect
	golang.org/x/net v0.24.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	gopkg.in/square/go-jose.v2 v2.6.0 // indirect
)

replace git.apache.org/thrift.git => github.com/apache/thrift v0.13.0
