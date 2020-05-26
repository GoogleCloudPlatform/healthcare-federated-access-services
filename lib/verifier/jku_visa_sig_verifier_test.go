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

package verifier

import (
	"context"
	"testing"
	"time"

	"github.com/coreos/go-oidc" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/errutil" /* copybara-comment: errutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/kms/localsign" /* copybara-comment: localsign */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */
)

func TestJKUVerifier_Verify(t *testing.T) {
	f, cleanup := newFix(t)
	defer cleanup()

	key := f.Issuer0.Keys[0]
	d := &ga4gh.VisaData{
		StdClaims: ga4gh.StdClaims{
			Issuer:    f.Issuer0.URL,
			Subject:   subject,
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
	}
	issuer := f.Issuer0.URL
	jku := jkuURL(issuer)
	signer := localsign.New(&key)
	visa, err := ga4gh.NewVisaFromData(context.Background(), d, jku, signer)
	if err != nil {
		t.Fatalf("ga4gh.NewVisaFromData() failed: %v", err)
	}

	// Make calls by oidc package use the fake HTTP client.
	ctx := oidc.ClientContext(context.Background(), f.HTTP.Client)

	v, err := NewVisaVerifier(ctx, issuer, jku, "")
	if err != nil {
		t.Fatalf("NewVisaVerifier() failed: %v", err)
	}

	if err := v.Verify(ctx, string(visa.JWT()), jku); err != nil {
		t.Errorf("VerifyPassportToken() failed: %v", err)
	}
}

func TestJKUVerifier_Verify_SecondIssuer(t *testing.T) {
	f, cleanup := newFix(t)
	defer cleanup()

	key := f.Issuer1.Keys[0]
	d := &ga4gh.VisaData{
		StdClaims: ga4gh.StdClaims{
			Issuer:    f.Issuer1.URL,
			Subject:   subject,
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
	}

	issuer := f.Issuer1.URL
	jku := jkuURL(issuer)
	signer := localsign.New(&key)
	visa, err := ga4gh.NewVisaFromData(context.Background(), d, jku, signer)
	if err != nil {
		t.Fatalf("ga4gh.NewVisaFromData() failed: %v", err)
	}

	// Make calls by oidc package use the fake HTTP client.
	ctx := oidc.ClientContext(context.Background(), f.HTTP.Client)

	v, err := NewVisaVerifier(ctx, issuer, jku, "")
	if err != nil {
		t.Fatalf("NewVisaVerifier() failed: %v", err)
	}

	if err := v.Verify(ctx, string(visa.JWT()), jku); err != nil {
		t.Errorf("VerifyPassportToken() failed: %v", err)
	}
}

func TestJKUVerifier_Verify_Fail_WrongJKUURL(t *testing.T) {
	f, cleanup := newFix(t)
	defer cleanup()

	key := f.Issuer0.Keys[0]
	d := &ga4gh.VisaData{
		StdClaims: ga4gh.StdClaims{
			Issuer:    f.Issuer0.URL,
			Subject:   subject,
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
	}
	issuer := f.Issuer0.URL
	jku := jkuURL(issuer) + "/wrong"
	signer := localsign.New(&key)
	visa, err := ga4gh.NewVisaFromData(context.Background(), d, jku, signer)
	if err != nil {
		t.Fatalf("ga4gh.NewVisaFromData() failed: %v", err)
	}

	// Make calls by oidc package use the fake HTTP client.
	ctx := oidc.ClientContext(context.Background(), f.HTTP.Client)

	v, err := NewVisaVerifier(ctx, issuer, jku, "")
	if err != nil {
		t.Fatalf("NewVisaVerifier() failed: %v", err)
	}

	if err := v.Verify(ctx, string(visa.JWT()), jku); errutil.ErrorReason(err) != errInvalidSignature {
		t.Errorf("VerifyPassportToken() = %s wants err: %s", errutil.ErrorReason(err), errInvalidSignature)
	}
}

func TestJKUVerifier_Verify_Fail_JKUNotMatch(t *testing.T) {
	f, cleanup := newFix(t)
	defer cleanup()

	key := f.Issuer0.Keys[0]
	d := &ga4gh.VisaData{
		StdClaims: ga4gh.StdClaims{
			Issuer:    f.Issuer0.URL,
			Subject:   subject,
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
	}
	issuer := f.Issuer0.URL
	jku := jkuURL(issuer)
	signer := localsign.New(&key)
	visa, err := ga4gh.NewVisaFromData(context.Background(), d, jku, signer)
	if err != nil {
		t.Fatalf("ga4gh.NewVisaFromData() failed: %v", err)
	}

	// Make calls by oidc package use the fake HTTP client.
	ctx := oidc.ClientContext(context.Background(), f.HTTP.Client)

	v, err := NewVisaVerifier(ctx, issuer, jkuURL(f.Issuer1.URL), "")
	if err != nil {
		t.Fatalf("NewVisaVerifier() failed: %v", err)
	}

	if err := v.Verify(ctx, string(visa.JWT()), jku); errutil.ErrorReason(err) != errJKUNotMatch {
		t.Errorf("VerifyPassportToken() = %s wants err: %s", errutil.ErrorReason(err), errJKUNotMatch)
	}
}

func TestJKUVerifier_Verify_Fail_IssuerNotMatch(t *testing.T) {
	f, cleanup := newFix(t)
	defer cleanup()

	key := f.Issuer0.Keys[0]
	d := &ga4gh.VisaData{
		StdClaims: ga4gh.StdClaims{
			Issuer:    f.Issuer0.URL,
			Subject:   subject,
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
	}
	issuer := f.Issuer0.URL
	jku := jkuURL(issuer)
	signer := localsign.New(&key)
	visa, err := ga4gh.NewVisaFromData(context.Background(), d, jku, signer)
	if err != nil {
		t.Fatalf("ga4gh.NewVisaFromData() failed: %v", err)
	}

	// Make calls by oidc package use the fake HTTP client.
	ctx := oidc.ClientContext(context.Background(), f.HTTP.Client)

	v, err := NewVisaVerifier(ctx, f.Issuer1.URL, jku, "")
	if err != nil {
		t.Fatalf("NewVisaVerifier() failed: %v", err)
	}

	if err := v.Verify(ctx, string(visa.JWT()), jku); errutil.ErrorReason(err) != errIssuerNotMatch {
		t.Errorf("VerifyPassportToken() = %s wants err: %s", errutil.ErrorReason(err), errIssuerNotMatch)
	}
}

func TestJKUVerifier_Verify_Fail_WrongKey(t *testing.T) {
	f, cleanup := newFix(t)
	defer cleanup()

	d := &ga4gh.VisaData{
		StdClaims: ga4gh.StdClaims{
			Issuer:    f.Issuer0.URL,
			Subject:   subject,
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
	}

	wrongKey := testkeys.Keys[testkeys.VisaIssuer1]
	issuer := f.Issuer0.URL
	jku := jkuURL(issuer)
	signer := localsign.New(&wrongKey)
	visa, err := ga4gh.NewVisaFromData(context.Background(), d, jku, signer)
	if err != nil {
		t.Fatalf("ga4gh.NewVisaFromData() failed: %v", err)
	}

	// Make calls by oidc package use the fake HTTP client.
	ctx := oidc.ClientContext(context.Background(), f.HTTP.Client)

	v, err := NewVisaVerifier(ctx, issuer, jku, "")
	if err != nil {
		t.Fatalf("NewVisaVerifier() failed: %v", err)
	}

	if err := v.Verify(ctx, string(visa.JWT()), jku); errutil.ErrorReason(err) != errInvalidSignature {
		t.Errorf("VerifyPassportToken() = %s wants err: %s", errutil.ErrorReason(err), errInvalidSignature)
	}
}

func TestJKUVerifier_Verify_IncludeClient(t *testing.T) {
	f, cleanup := newFix(t)
	defer cleanup()

	key := f.Issuer0.Keys[0]
	d := &ga4gh.VisaData{
		StdClaims: ga4gh.StdClaims{
			Issuer:    f.Issuer0.URL,
			Subject:   subject,
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
			Audience:  []string{client},
		},
	}

	issuer := f.Issuer0.URL
	jku := jkuURL(issuer)
	signer := localsign.New(&key)
	visa, err := ga4gh.NewVisaFromData(context.Background(), d, jku, signer)
	if err != nil {
		t.Fatalf("ga4gh.NewVisaFromData() failed: %v", err)
	}

	// Make calls by oidc package use the fake HTTP client.
	ctx := oidc.ClientContext(context.Background(), f.HTTP.Client)

	v, err := NewVisaVerifier(ctx, issuer, jku, "fake-")
	if err != nil {
		t.Fatalf("NewVisaVerifier() failed: %v", err)
	}

	if err := v.Verify(ctx, string(visa.JWT()), jku); err != nil {
		t.Errorf("VerifyPassportToken() failed: %v", err)
	}
}

func TestJKUVerifier_Verify_Fail_TokenExpired(t *testing.T) {
	f, cleanup := newFix(t)
	defer cleanup()

	key := f.Issuer0.Keys[0]
	d := &ga4gh.VisaData{
		StdClaims: ga4gh.StdClaims{
			Issuer:    f.Issuer0.URL,
			Subject:   subject,
			ExpiresAt: time.Now().Add(-time.Hour).Unix(),
		},
	}

	issuer := f.Issuer0.URL
	jku := jkuURL(issuer)
	signer := localsign.New(&key)
	visa, err := ga4gh.NewVisaFromData(context.Background(), d, jku, signer)
	if err != nil {
		t.Fatalf("ga4gh.NewVisaFromData() failed: %v", err)
	}

	// Make calls by oidc package use the fake HTTP client.
	ctx := oidc.ClientContext(context.Background(), f.HTTP.Client)

	v, err := NewVisaVerifier(ctx, issuer, jku, "")
	if err != nil {
		t.Fatalf("NewVisaVerifier() failed: %v", err)
	}

	if err := v.Verify(ctx, string(visa.JWT()), jku); errutil.ErrorReason(err) != errExpired {
		t.Errorf("VerifyPassportToken() = %s wants err: %s", errutil.ErrorReason(err), errExpired)
	}
}

func TestJKUVerifier_Verify_Fail_FutureToken(t *testing.T) {
	f, cleanup := newFix(t)
	defer cleanup()

	tests := []struct {
		name  string
		claim *ga4gh.VisaData
	}{
		{
			name: "nbf",
			claim: &ga4gh.VisaData{
				StdClaims: ga4gh.StdClaims{
					Issuer:    f.Issuer0.URL,
					Subject:   subject,
					ExpiresAt: time.Now().Add(time.Hour).Unix(),
					NotBefore: time.Now().Add(time.Hour).Unix(),
				},
			},
		},
		{
			name: "iat",
			claim: &ga4gh.VisaData{
				StdClaims: ga4gh.StdClaims{
					Issuer:    f.Issuer0.URL,
					Subject:   subject,
					ExpiresAt: time.Now().Add(time.Hour).Unix(),
					IssuedAt:  time.Now().Add(time.Hour).Unix(),
				},
			},
		},
	}

	key := f.Issuer0.Keys[0]
	signer := localsign.New(&key)

	// Make calls by oidc package use the fake HTTP client.
	ctx := oidc.ClientContext(context.Background(), f.HTTP.Client)

	issuer := f.Issuer0.URL
	jku := jkuURL(issuer)

	v, err := NewVisaVerifier(ctx, issuer, jku, "")
	if err != nil {
		t.Fatalf("NewVisaVerifier() failed: %v", err)
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			visa, err := ga4gh.NewVisaFromData(context.Background(), tc.claim, jku, signer)
			if err != nil {
				t.Fatalf("ga4gh.NewVisaFromData() failed: %v", err)
			}

			if err := v.Verify(ctx, string(visa.JWT()), jku); errutil.ErrorReason(err) != errFutureToken {
				t.Errorf("VerifyPassportToken() = %s wants err: %s", errutil.ErrorReason(err), errFutureToken)
			}
		})
	}
}

func TestJKUVerifier_Verify_Visa_Aud(t *testing.T) {
	f, cleanup := newFix(t)
	defer cleanup()

	// Create and sign a Visa using the Issuer's private key.
	key := f.Issuer0.Keys[0]

	signer := localsign.New(&key)

	// Make calls by oidc package use the fake HTTP client.
	ctx := oidc.ClientContext(context.Background(), f.HTTP.Client)

	issuer := f.Issuer0.URL
	jku := jkuURL(issuer)
	v, err := NewVisaVerifier(ctx, issuer, jku, "example.com")
	if err != nil {
		t.Fatalf("NewVisaVerifier() failed: %v", err)
	}

	tests := []struct {
		name    string
		aud     ga4gh.Audiences
		errType string
	}{
		{
			name: "empty",
			aud:  []string{},
		},
		{
			name: "prefix found",
			aud:  []string{"a", "example.com/a"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := &ga4gh.VisaData{
				StdClaims: ga4gh.StdClaims{
					Issuer:    f.Issuer0.URL,
					Subject:   subject,
					ExpiresAt: time.Now().Add(time.Hour).Unix(),
					Audience:  tc.aud,
				},
			}

			visa, err := ga4gh.NewVisaFromData(context.Background(), d, jku, signer)
			if err != nil {
				t.Fatalf("ga4gh.NewVisaFromData() failed: %v", err)
			}

			if err := v.Verify(ctx, string(visa.JWT()), jku); err != nil {
				t.Errorf("VerifyPassportToken() failed: %v", err)
			}
		})
	}

	t.Run("not found", func(t *testing.T) {
		d := &ga4gh.VisaData{
			StdClaims: ga4gh.StdClaims{
				Issuer:    f.Issuer0.URL,
				Subject:   subject,
				ExpiresAt: time.Now().Add(time.Hour).Unix(),
				Audience:  []string{"a", "b"},
			},
		}

		visa, err := ga4gh.NewVisaFromData(context.Background(), d, jku, signer)
		if err != nil {
			t.Fatalf("ga4gh.NewVisaFromData() failed: %v", err)
		}

		if err := v.Verify(ctx, string(visa.JWT()), jku); errutil.ErrorReason(err) != errInvalidAudience {
			t.Errorf("VerifyPassportToken() = %s wants err: %s", errutil.ErrorReason(err), errInvalidAudience)
		}
	})
}
