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
	"log"

	"cloud.google.com/go/kms/apiv1"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/kms/gcpcrypt"
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
		log.Fatalf("Need project, keyring and key for real CloudKMS test")
	}

	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		log.Fatalf("NewKeyManagementClient(ctx, clientOpt) failed: %v", err)
	}
	s, err := gcpcrypt.New(ctx, *project, *location, *keyring, *keyname, client)
	if err != nil {
		log.Fatalf("kmssymmetric.New(ctx, %q, %q, %q, %q): %v", *project, *location, *keyring, *keyname, err)
	}
	log.Printf("Runing test on real gcp kms service, project=%q, location=%q, keyring=%q, key=%q\n", *project, *location, *keyring, *keyname)

	const additionalAuthData = "aad"
	data := []byte("This is a message.")

	ciphertext, err := s.Encrypt(ctx, data, additionalAuthData)
	if err != nil {
		log.Fatal(err)
	}

	plaintext, err := s.Decrypt(ctx, ciphertext, additionalAuthData)
	if err != nil {
		log.Fatal(err)
	}

	if !bytes.Equal(plaintext, data) {
		log.Fatalf("s.Decrypt(encrypted.Encrypted, kid, additionalAuthData) = %v, wants %v", plaintext, data)
	}

	// Decrypt with wrong additionalAuthData
	if _, err := s.Decrypt(ctx, ciphertext, "wrong"); err == nil {
		log.Fatal("s.Decrypt(encrypted.Encrypted, kid, 'wrong') wants error")
	}
	log.Println("PASS")
}
