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

package fakegrpc

import (
	"testing"
)

func TestNew(t *testing.T) {
	rpc, cleanup := New(t)
  defer cleanup()

  // Register your server using rpc.Server.
  // s := &Server{}
  // fgrpcpb.RegisterFooServiceServer(rpc.Server, s)

	stop := rpc.Start(t)
  defer stop()

  // Create a client using rpc.Client.
  // c := foo.NewClient(ctx,
  //   option.WithGRPCConn(rpc.Client),
  //   option.WithoutAuthentication(),
  //   option.WithGRPCDialOption(grpc.WithInsecure()),
  // )

  // Inject the client into your code.

  // Run the code under the test.

  // Check test post-conditions using s.
}
