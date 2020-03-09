// Copyright 2020 Google LLC
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
	"context"

	glog "github.com/golang/glog" /* copybara-comment */
	"google.golang.org/grpc" /* copybara-comment */
)

// UnaryLoggerInterceptor intercepts calls to the server and logs the request and response.
func UnaryLoggerInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	glog.Infof("ServerRPCRequest: %T:%+v", req, req)
	resp, err := handler(ctx, req)
	glog.Infof("ServerRPCResponse: %T:%+v, err:%v", resp, resp, err)
	return resp, err
}

// LoggerStream wraps around the embedded grpc.ServerStream, and intercepts the RecvMsg and SendMsg method call and logs them.
type LoggerStream struct {
	grpc.ServerStream
}

// RecvMsg recieves a message.
func (w *LoggerStream) RecvMsg(m interface{}) error {
	glog.Infof("ServerStream.RecvMsg (Type: %T): %+v", m, m)
	return w.ServerStream.RecvMsg(m)
}

// SendMsg sends a message.
func (w *LoggerStream) SendMsg(m interface{}) error {
	glog.Infof("ServerStream.SendMsg (Type: %T): %+v", m, m)
	return w.ServerStream.SendMsg(m)
}

// StreamLoggerInterceptor intercepts streams to the server and logs the messages.
func StreamLoggerInterceptor(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	return handler(srv, &LoggerStream{ss})
}
