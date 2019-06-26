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

package common

import (
	"net/http/httptest"
	"testing"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/common/models"
)

func assertHeader(t *testing.T, w *httptest.ResponseRecorder, header string, expect string) {
	if w.Header().Get(header) != expect {
		t.Errorf("Wants header %q is %q, Got %q", header, expect, w.Header().Get(header))
	}
}

func TestSendResponse(t *testing.T) {
	w := httptest.NewRecorder()

	msg := &models.LoginState{}

	err := SendResponse(msg, w)
	if err != nil {
		t.Fatalf("SendResponse failed. %q", err)
	}

	assertHeader(t, w, "Content-Type", "application/json")
	assertHeader(t, w, "Cache-Control", "no-store")
	assertHeader(t, w, "Pragma", "no-cache")
	assertHeader(t, w, "Access-Control-Allow-Origin", "*")
	assertHeader(t, w, "Access-Control-Allow-Headers", "Content-Type, Origin, Accept, Authorization")
	assertHeader(t, w, "Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
}
