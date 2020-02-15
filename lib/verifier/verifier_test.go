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

package verifier

import (
	"context"
	"testing"
	"time"

	"github.com/coreos/go-oidc" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakehttp" /* copybara-comment: fakehttp */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakeissuer" /* copybara-comment: fakeissuer */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */
)

const (
	client  = "fake-client"
	subject = "fake-subject"
)

// fix is a test fixture.
type fix struct {
	HTTP    *fakehttp.HTTP
	Issuer0 *fakeissuer.Issuer
	Issuer1 *fakeissuer.Issuer
}

func newFix(t *testing.T) (*fix, func()) {
	t.Helper()

	h, hc := fakehttp.New()

	// Setup Issuer0
	key0 := testkeys.Keys[testkeys.VisaIssuer0]
	key0.ID = h.Server.URL + "/issuer0"
	i0 := fakeissuer.New(key0.ID, key0)

	// Setup Issuer1
	key1 := testkeys.Keys[testkeys.VisaIssuer1]
	key1.ID = h.Server.URL + "/issuer1"
	i1 := fakeissuer.New(key1.ID, key1)

	h.Handler = fakehttp.PrefixHandlers{
		"/issuer0": i0.Handler,
		"/issuer1": i1.Handler,
	}.Handler

	cleanup := func() { hc() }
	return &fix{
		HTTP:    h,
		Issuer0: i0,
		Issuer1: i1,
	}, cleanup
}

func TestVerifier_Verify(t *testing.T) {
	f, cleanup := newFix(t)
	defer cleanup()

	// Create and sign a Visa using the Issuer's private key.
	key := f.Issuer0.Keys[0]
	d := &ga4gh.VisaData{
		StdClaims: ga4gh.StdClaims{
			Issuer:    key.ID,
			Subject:   subject,
			Audience:  ga4gh.NewAudience(client),
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
	}
	visa, err := ga4gh.NewVisaFromData(d, ga4gh.RS256, key.Private, key.ID)
	if err != nil {
		t.Fatalf("ga4gh.NewVisaFromData() failed: %v", err)
	}

	// Make calls by oidc package use the fake HTTP client.
	ctx := oidc.ClientContext(context.Background(), f.HTTP.Client)

	v := New(client)

	if err := v.Verify(ctx, string(visa.JWT())); err != nil {
		t.Fatalf("Verifier.Verify(_,_) failed: %v", err)
	}
}

func TestVerifier_Verify_EmptyClientID(t *testing.T) {
	f, cleanup := newFix(t)
	defer cleanup()

	// Create and sign a Visa using the Issuer's private key.
	key := f.Issuer0.Keys[0]
	d := &ga4gh.VisaData{
		StdClaims: ga4gh.StdClaims{
			Issuer:    key.ID,
			Subject:   subject,
			Audience:  ga4gh.NewAudience(client),
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
	}
	visa, err := ga4gh.NewVisaFromData(d, ga4gh.RS256, key.Private, key.ID)
	if err != nil {
		t.Fatalf("ga4gh.NewVisaFromData() failed: %v", err)
	}

	// Make calls by oidc package use the fake HTTP client.
	ctx := oidc.ClientContext(context.Background(), f.HTTP.Client)

	// An audience is specified in the token. If the verifier does not specify a client,
	// the verifier should fail since we cannot confirm we are the intended audience.
	v := New("")

	if err := v.Verify(ctx, string(visa.JWT())); err == nil {
		t.Fatalf("Verifier.Verify(_,_) unexpected success when audience cannot be confirmed")
	}
}

func TestVerifier_Verify_SecondIssuer(t *testing.T) {
	f, cleanup := newFix(t)
	defer cleanup()

	// Create and sign a Visa using the Issuer's private key.
	key := f.Issuer1.Keys[0]
	d := &ga4gh.VisaData{
		StdClaims: ga4gh.StdClaims{
			Issuer:    key.ID,
			Subject:   subject,
			Audience:  ga4gh.NewAudience(client),
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
	}

	visa, err := ga4gh.NewVisaFromData(d, ga4gh.RS256, key.Private, key.ID)
	if err != nil {
		t.Fatalf("ga4gh.NewVisaFromData() failed: %v", err)
	}

	// Make calls by oidc package use the fake HTTP client.
	ctx := oidc.ClientContext(context.Background(), f.HTTP.Client)

	v := New(client)

	if err := v.Verify(ctx, string(visa.JWT())); err != nil {
		t.Fatalf("Verifier.Verify(_,_) failed: %v", err)
	}
}

func TestVerifier_Verify_Fail_WrongIssuerURL(t *testing.T) {
	f, cleanup := newFix(t)
	defer cleanup()

	// Create and sign a Visa using the Issuer's private key.
	key := f.Issuer0.Keys[0]
	d := &ga4gh.VisaData{
		StdClaims: ga4gh.StdClaims{
			Issuer:    f.HTTP.Server.URL + "/wrong-issuer-url",
			Subject:   subject,
			Audience:  ga4gh.NewAudience(client),
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
	}
	visa, err := ga4gh.NewVisaFromData(d, ga4gh.RS256, key.Private, key.ID)
	if err != nil {
		t.Fatalf("ga4gh.NewVisaFromData() failed: %v", err)
	}

	// Make calls by oidc package use the fake HTTP client.
	ctx := oidc.ClientContext(context.Background(), f.HTTP.Client)

	v := New(client)

	if err := v.Verify(ctx, string(visa.JWT())); err == nil {
		t.Fatal("Verifier.Verify(_,_) should fail when issuer URL is wrong.")
	}
}

func TestVerifier_Verify_Fail_WrongKey(t *testing.T) {
	f, cleanup := newFix(t)
	defer cleanup()

	// Create and sign a Visa using the Issuer's private key.
	key := f.Issuer0.Keys[0]
	d := &ga4gh.VisaData{
		StdClaims: ga4gh.StdClaims{
			Issuer:    key.ID,
			Subject:   subject,
			Audience:  ga4gh.NewAudience(client),
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
	}

	wrongKey := testkeys.Keys[testkeys.VisaIssuer1]
	visa, err := ga4gh.NewVisaFromData(d, ga4gh.RS256, wrongKey.Private, key.ID)
	if err != nil {
		t.Fatalf("ga4gh.NewVisaFromData() failed: %v", err)
	}

	// Make calls by oidc package use the fake HTTP client.
	ctx := oidc.ClientContext(context.Background(), f.HTTP.Client)

	v := New(client)

	if err := v.Verify(ctx, string(visa.JWT())); err == nil {
		t.Fatal("Verifier.Verify(_,_) should fail when key is wrong.")
	}
}

func TestVerifier_Verify_Fail_WrongClient(t *testing.T) {
	f, cleanup := newFix(t)
	defer cleanup()

	// Create and sign a Visa using the Issuer's private key.
	key := f.Issuer0.Keys[0]
	d := &ga4gh.VisaData{
		StdClaims: ga4gh.StdClaims{
			Issuer:    key.ID,
			Subject:   subject,
			Audience:  ga4gh.NewAudience("wrong-client"),
			ExpiresAt: time.Now().Add(-time.Hour).Unix(),
		},
	}

	visa, err := ga4gh.NewVisaFromData(d, ga4gh.RS256, key.Private, key.ID)
	if err != nil {
		t.Fatalf("ga4gh.NewVisaFromData() failed: %v", err)
	}

	// Make calls by oidc package use the fake HTTP client.
	ctx := oidc.ClientContext(context.Background(), f.HTTP.Client)

	v := New(client)

	if err := v.Verify(ctx, string(visa.JWT())); err == nil {
		t.Fatal("Verifier.Verify(_,_) should fail when token has expired.")
	}
}

func TestVerifier_Verify_Fail_TokenExpired(t *testing.T) {
	f, cleanup := newFix(t)
	defer cleanup()

	// Create and sign a Visa using the Issuer's private key.
	key := f.Issuer0.Keys[0]
	d := &ga4gh.VisaData{
		StdClaims: ga4gh.StdClaims{
			Issuer:    key.ID,
			Subject:   subject,
			Audience:  ga4gh.NewAudience(client),
			ExpiresAt: time.Now().Add(-time.Hour).Unix(),
		},
	}

	visa, err := ga4gh.NewVisaFromData(d, ga4gh.RS256, key.Private, key.ID)
	if err != nil {
		t.Fatalf("ga4gh.NewVisaFromData() failed: %v", err)
	}

	// Make calls by oidc package use the fake HTTP client.
	ctx := oidc.ClientContext(context.Background(), f.HTTP.Client)

	v := New(client)

	if err := v.Verify(ctx, string(visa.JWT())); err == nil {
		t.Fatal("Verifier.Verify(_,_) should fail when token has expired.")
	}
}
