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

package httputil

import (
	"encoding/json"
	"net/http"

	glog "github.com/golang/glog"
)

// WriteRPCResp writes reponse and error.
// Can be used to create an HTTP handler from a GRPC handler.
//
//  func (h *FooHTTPHandler) GetFoo(w http.ResponseWriter, r *http.Request) {
// 	  req := &fpb.GetFooRequest{Name: r.RequestURI}
// 	  resp := &fpb.Foo{}
// 	  err := fooServer.GetFoo(r.Context(), req, resp)
// 	  WriteRPCResp(w, resp, err)
//   }
//
// To return the detailed RPC Status error back to client as response, use:
//   WriteRPCResp(w, status.Convert(err).Proto(), nil)
//
// TODO: reconcile and ensure consistency with
//                  common.NewStatus() and common.SendStatus().
func WriteRPCResp(w http.ResponseWriter, resp interface{}, err error) {
	if err != nil {
		code := FromError(err)
		http.Error(w, err.Error(), code)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		glog.Errorf("json.NewEncoder(writer).Encode(resp) failed: %v", err)
		http.Error(w, "encoding the response failed", http.StatusInternalServerError)
		return
	}
}
