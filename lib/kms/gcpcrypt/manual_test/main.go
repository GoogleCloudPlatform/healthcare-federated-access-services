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

// Binary gcpcrypt contains a symmetric encryption test run on real CloudKMS.
package main

import (
	"bytes"
	"context"
	"flag"

	glog "github.com/golang/glog" /* copybara-comment */
	"cloud.google.com/go/kms/apiv1" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/kms/gcpcrypt" /* copybara-comment: gcpcrypt */
)

var (
	project  = flag.String("project", "", "project for encryption")
	location = flag.String("location", "global", "location of keyring")
	keyring  = flag.String("keyring", "", "name of keyring")
	keyname  = flag.String("key", "", "name of key")
)

func main() {
	ctx := context.Background()

	flag.Parse()
	if len(*project) == 0 || len(*keyring) == 0 || len(*keyname) == 0 {
		glog.Fatalf("Need project, keyring and key for real CloudKMS test")
	}

	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		glog.Fatalf("NewKeyManagementClient(ctx, clientOpt) failed: %v", err)
	}
	s, err := gcpcrypt.New(ctx, *project, *location, *keyring, *keyname, client)
	if err != nil {
		glog.Fatalf("kmssymmetric.New(ctx, %q, %q, %q, %q): %v", *project, *location, *keyring, *keyname, err)
	}
	glog.Infof("Runing test on real gcp kms service, project=%q, location=%q, keyring=%q, key=%q\n", *project, *location, *keyring, *keyname)

	const additionalAuthData = "aad"
	data := []byte("This is a message.")

	ciphertext, err := s.Encrypt(ctx, data, additionalAuthData)
	if err != nil {
		glog.Fatal(err)
	}

	plaintext, err := s.Decrypt(ctx, ciphertext, additionalAuthData)
	if err != nil {
		glog.Fatal(err)
	}

	if !bytes.Equal(plaintext, data) {
		glog.Fatalf("s.Decrypt(encrypted.Encrypted, kid, additionalAuthData) = %v, wants %v", plaintext, data)
	}

	// Decrypt with wrong additionalAuthData
	if _, err := s.Decrypt(ctx, ciphertext, "wrong"); err == nil {
		glog.Fatal("s.Decrypt(encrypted.Encrypted, kid, 'wrong') wants error")
	}
	glog.Infoln("PASS")
}
