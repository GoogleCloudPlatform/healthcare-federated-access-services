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
	"reflect"
	"testing"
	"time"

	"github.com/coreos/go-oidc" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/errutil" /* copybara-comment: errutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/kms/localsign" /* copybara-comment: localsign */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakehttp" /* copybara-comment: fakehttp */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakeissuer" /* copybara-comment: fakeissuer */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */
)

func TestNewVisaVerifier(t *testing.T) {
	f, cleanup := newFix(t)
	defer cleanup()

	tests := []struct {
		name   string
		issuer string
		jku    string
		want   string
	}{
		{
			name:   "jku",
			issuer: f.Issuer0.URL,
			jku:    jkuURL(f.Issuer0.URL),
			want:   "*verifier.jkuVisaSigVerifier",
		},
		{
			name:   "no jku",
			issuer: f.Issuer0.URL,
			want:   "*verifier.oidcJwtSigVerifier",
		},
	}

	ctx := oidc.ClientContext(context.Background(), f.HTTP.Client)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, err := NewVisaVerifier(ctx, tc.issuer, tc.jku, "")
			if err != nil {
				t.Fatalf("NewVisaVerifier() failed: %v", err)
			}

			got := reflect.TypeOf(v.tok).String()
			if got != tc.want {
				t.Errorf("NewVisaVerifier() = %s, wants %s", got, tc.want)
			}
		})
	}
}

func TestVerifyVisaToken_WrongType(t *testing.T) {
	f, cleanup := newFix(t)
	defer cleanup()

	ctx := oidc.ClientContext(context.Background(), f.HTTP.Client)

	jkuVerifier, err := NewVisaVerifier(ctx, f.Issuer0.URL, jkuURL(f.Issuer0.URL), "")
	if err != nil {
		t.Fatalf("NewVisaVerifier() failed: %v", err)
	}

	oidcVerifier, err := NewVisaVerifier(ctx, f.Issuer0.URL, "", "")
	if err != nil {
		t.Fatalf("NewVisaVerifier() failed: %v", err)
	}

	tests := []struct {
		name     string
		jku      string
		verifier *VisaVerifier
	}{
		{
			name:     "jku",
			jku:      jkuURL(f.Issuer0.URL),
			verifier: oidcVerifier,
		},
		{
			name:     "no jku",
			verifier: jkuVerifier,
		},
	}

	d := &ga4gh.VisaData{
		StdClaims: ga4gh.StdClaims{
			Issuer:    f.Issuer0.URL,
			Subject:   subject,
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		},
	}
	key := f.Issuer0.Keys[0]
	signer := localsign.New(&key)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			visa, err := ga4gh.NewVisaFromData(context.Background(), d, tc.jku, signer)
			if err != nil {
				t.Fatalf("ga4gh.NewVisaFromData() failed: %v", err)
			}

			if err := tc.verifier.Verify(ctx, string(visa.JWT()), tc.jku); errutil.ErrorReason(err) != errVerifierInvalidType {
				t.Errorf("VerifyPassportToken() wants err: %s", errVerifierInvalidType)
			}
		})
	}
}

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

func jkuURL(issuer string) string {
	return issuer + "/.well-known/jwks"
}
