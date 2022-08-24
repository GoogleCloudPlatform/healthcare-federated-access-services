// Copyright 2020 Google LLC.
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

// Binary gcpsign contains a signning test run on real CloudKMS.
package main

import (
	"context"
	"crypto/rsa"
	"flag"
	"time"

	"google3/third_party/golang/cloud_google_com/go/kms/v/v0/apiv1/kms"
	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"github.com/google/go-cmp/cmp/cmpopts" /* copybara-comment */
	"gopkg.in/square/go-jose.v2" /* copybara-comment */
	"gopkg.in/square/go-jose.v2/jwt" /* copybara-comment */
	"github.com/coreos/go-oidc" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/kms/gcpsign" /* copybara-comment: gcpsign */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/persona" /* copybara-comment: persona */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/httptestclient" /* copybara-comment: httptestclient */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */

	glog "github.com/golang/glog" /* copybara-comment */
)

var (
	project  = flag.String("project", "bamboo-velocity-275115", "project for encryption")
	location = flag.String("location", "global", "location of keyring")
	keyring  = flag.String("keyring", "kr", "name of keyring")
	keyname  = flag.String("key", "k", "name of key")
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
	s, err := gcpsign.New(ctx, *project, *location, *keyring, *keyname, client)
	if err != nil {
		glog.Fatalf("gcpsign.New(ctx, %q, %q, %q, %q, client): %v", *project, *location, *keyring, *keyname, err)
	}
	glog.Infof("Runing test on real gcp kms service, project=%q, location=%q, keyring=%q, key=%q\n", *project, *location, *keyring, *keyname)

	iss := "http://iss.example.com"
	clientID := "client-1234"
	sub := "sub-1234"
	claims := jwt.Claims{
		Issuer:   iss,
		Subject:  sub,
		Expiry:   jwt.NewNumericDate(time.Now().Add(10 * time.Hour)),
		Audience: []string{clientID},
	}

	header := map[string]string{
		"jku": "http://iss.example.com/.well-known/jwks",
	}

	tok, err := s.SignJWT(ctx, claims, header)
	if err != nil {
		glog.Fatal("SignJWT() failed", err)
	}
	glog.Infof("jwt: %s", tok)
	glog.Infof("public keys: %+v\n", s.PublicKeys())

	pub, ok := s.PublicKeys().Keys[0].Key.(*rsa.PublicKey)
	if !ok {
		glog.Fatalf("s.PublicKeys().Keys[0].Key type incorrect %T", s.PublicKeys().Keys[0].Key)
	}

	// setup a fake oidc provider to test jwt verify.
	key := &testkeys.Key{
		Public: pub,
		ID:     s.PublicKeys().Keys[0].KeyID,
	}
	op, err := persona.NewBroker(iss, key, "", "", false)
	if err != nil {
		glog.Fatal("persona.NewBroker() failed", err)
	}

	withClient := oidc.ClientContext(ctx, httptestclient.New(op.Handler))
	p, err := oidc.NewProvider(withClient, iss)
	if err != nil {
		glog.Fatalf("oidc.NewProvider failed: %v", err)
	}

	idt, err := p.Verifier(&oidc.Config{ClientID: clientID}).Verify(withClient, tok)
	if err != nil {
		glog.Fatalf("oidc.Verify failed: %v", err)
	}

	if idt.Subject != sub {
		glog.Fatalf("sub = %s, wants %s", idt.Subject, sub)
	}

	t, err := jwt.ParseSigned(tok)
	if err != nil {
		glog.Fatalf("jwt.ParseSigned() failed: %v", err)
	}

	if len(t.Headers) != 1 {
		glog.Fatalf("len(t.Headers) %d, wants 1", len(t.Headers))
	}

	wantHeader := jose.Header{
		KeyID:     s.PublicKeys().Keys[0].KeyID,
		Algorithm: "RS256",
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"jku": "http://iss.example.com/.well-known/jwks",
			"typ": "JWT",
		},
	}

	if d := cmp.Diff(wantHeader, t.Headers[0], cmpopts.IgnoreUnexported(jose.Header{})); len(d) > 0 {
		glog.Fatalf("header (-want, +got): %s", d)
	}

	glog.Infoln("PASS")
}
