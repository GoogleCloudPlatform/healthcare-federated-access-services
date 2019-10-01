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

// example is an example of how to use ga4gh package.
package main

import (
	"time"

	glog "github.com/golang/glog"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys"
)

func main() {
	a := ga4gh.Assertion{
		Type:       "fake-claim-type",
		Value:      "fake-claim-value",
		Source:     "fake-claim-source",
		Asserted:   time.Now().Add(-time.Hour).Unix(),
		By:         "fake-claim-by",
		Conditions: [][]ga4gh.Condition{},
	}
	r := ClaimRepository{Assertion: a}
	i := VisaIssuer{R: &r, Key: testkeys.Keys[testkeys.VisaIssuer0]}
	b := PassportBroker{I: &i, Key: testkeys.Keys[testkeys.PassportBroker0]}
	c := PassportClearinghouse{B: &b}

	resource := Resource("gcs-bucket")
	token := Token("alice")
	access, err := c.RequestAccess(resource, token)
	if err != nil {
		glog.Exitf("RequestAccess(%q,%v) failed:\n%v", resource, token, err)
	}
	glog.Infof("Access token for %q:%q", resource, access)
}
