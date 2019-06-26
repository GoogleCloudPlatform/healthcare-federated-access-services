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

package translator

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"
	"time"

	"gopkg.in/square/go-jose.v2/jwt"
	"github.com/coreos/go-oidc"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/common"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services"
)

const (
	// TODO(cdvoisin): Update the issuer address once NCBI stands up their own OIDC endpoint.
	dbGapIssuer = "https://dbgap.nlm.nih.gov/aa"
	dbGapOrgURL = "https://orgs.nih.gov/orgs/"
)

// DbGapTranslator is a ga4gh.Translator that converts dbGap identities into GA4GH identities.
type DbGapTranslator struct {
	publicKey *rsa.PublicKey
}

type dbGapStudy struct {
	Accession *string `json:"accession"`
}

type dbGapAccess struct {
	Study   dbGapStudy `json:"study"`
	Expires float64    `json:"expires"`
	Issued  float64    `json:"issued"`
}

type dbGapPassport struct {
	Access []dbGapAccess `json:"access"`
	Org    *string       `json:"org"`
	OrgID  *string       `json:"org_DUNS"`
	Role   *string       `json:"role"`
	SO     *string       `json:"so"`
}

type dbGapClaims struct {
	DbGapPassport []dbGapPassport `json:"dbgap_passport"`
}

// idToken mocks OIDC library's idToken implementation, except minor differences in the types of
// Audience, Expiry, and IssuedAt fields to facilitate JSON unmarshalling.
type idToken struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience string `json:"aud"`
	Expiry   int64  `json:"exp"`
	IssuedAt int64  `json:"iat"`
	Nonce    string `json:"nonce"`
	AtHash   string `json:"at_hash"`
}

const validSec = 3600 * 24 * 60 // 60 days

var removePunctuation = regexp.MustCompile("[^a-zA-Z0-9 ]+")

func convertToOIDCIDToken(token idToken) *oidc.IDToken {
	return &oidc.IDToken{
		Issuer:          token.Issuer,
		Subject:         token.Subject,
		Audience:        []string{token.Audience},
		Expiry:          time.Unix(token.Expiry, 0),
		IssuedAt:        time.Unix(token.IssuedAt, 0),
		Nonce:           token.Nonce,
		AccessTokenHash: token.AtHash,
	}
}

// NewDbGapTranslator creates a new DbGapTranslator with the provided public key. If the tokens
// passed to this translator do not have an audience claim with a value equal to the
// clientID value then they will be rejected.
func NewDbGapTranslator(publicKey string) (*DbGapTranslator, error) {
	// TODO(cdvoisin): Create an ID token verifier once issuer endpoint has been setup.
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return &DbGapTranslator{}, nil
	}
	k, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %v", err)
	}
	return &DbGapTranslator{publicKey: k}, nil
}

// TranslateToken implements the ga4gh.Translator interface.
func (s *DbGapTranslator) TranslateToken(ctx context.Context, auth string) (*ga4gh.Identity, error) {
	if err := common.VerifyTokenWithKey(s.publicKey, auth); err != nil {
		return nil, fmt.Errorf("verifying token signature: %v", err)
	}
	var claims dbGapClaims
	var id idToken
	parsed, err := jwt.ParseSigned(auth)
	if err != nil {
		return nil, fmt.Errorf("parsing signed ID token: %v", err)
	}
	err = parsed.UnsafeClaimsWithoutVerification(&id, &claims)
	if err != nil {
		return nil, fmt.Errorf("extracting claims from token: %v", err)
	}
	return s.translateToken(convertToOIDCIDToken(id), claims, time.Now())
}

func (s *DbGapTranslator) translateToken(token *oidc.IDToken, claims dbGapClaims, now time.Time) (*ga4gh.Identity, error) {
	id := ga4gh.Identity{
		Issuer:  token.Issuer,
		Subject: token.Subject,
		Expiry:  token.Expiry.Unix(),
		GA4GH:   make(map[string][]ga4gh.Claim),
	}
	accessions := make(map[string]dbGapAccess)
	type source struct {
		orgID string
		by    string
	}
	affiliations := make(map[string]source)
	for _, p := range claims.DbGapPassport {
		for _, a := range p.Access {
			if a.Study.Accession == nil {
				continue
			}
			// TODO(cdvoisin): Verify that the heuristics for de-duplicating access entries is correct.
			ac := *a.Study.Accession
			exp := a.Expires
			if access, ok := accessions[ac]; ok {
				// For duplicate accessions, only keep the one with the later expiry timestamp.
				if access.Expires > exp {
					continue
				}
			}
			accessions[ac] = dbGapAccess{
				Expires: exp,
				Issued:  a.Issued,
			}
		}
		if p.Org == nil || len(*p.Org) == 0 || p.Role == nil || len(*p.Role) == 0 {
			continue
		}
		var r string
		if *p.Role == "pi" || *p.Role == "downloader" {
			r = "researcher"
		} else {
			r = "member"
		}
		o := removePunctuation.ReplaceAllString(*p.Org, "")
		o = strings.ReplaceAll(o, " ", "-")
		v := r + "@" + o + ".orgs.nih.gov"
		// Does not deal with complex cases where multiple org_DUNS attest to the same
		// "value" (v) for AffiliationAndRole.
		if src, ok := affiliations[v]; !ok || src.by == "self" {
			by := "so"
			if p.SO == nil || *p.SO == "" {
				by = "self"
			}
			affiliations[v] = source{
				orgID: *p.OrgID,
				by:    by,
			}
		}
	}

	currUnixTime := now.Unix()
	affiliationAsserted := float64(currUnixTime)
	for a, val := range accessions {
		id.GA4GH[ga4gh.ClaimControlledAccessGrants] = append(id.GA4GH[ga4gh.ClaimControlledAccessGrants],
			ga4gh.Claim{
				Value:    "https://dac.nih.gov/datasets/" + a,
				Source:   dbGapIssuer,
				Asserted: val.Issued,
				Expires:  val.Expires,
				By:       "dac",
			})
		// Keep the oldest Issued accession for use as affiliationAsserted.
		if val.Issued > 0 && val.Issued < affiliationAsserted {
			affiliationAsserted = val.Issued
		}
	}
	for a, src := range affiliations {
		id.GA4GH[ga4gh.ClaimAffiliationAndRole] = append(id.GA4GH[ga4gh.ClaimAffiliationAndRole],
			ga4gh.Claim{
				Value:    a,
				Source:   dbGapOrgURL + src.orgID,
				Asserted: affiliationAsserted,
				Expires:  float64(currUnixTime + validSec),
				By:       src.by,
			},
			ga4gh.Claim{
				Value:    a,
				Source:   dbGapIssuer,
				Asserted: affiliationAsserted,
				Expires:  float64(currUnixTime + validSec),
				By:       "system",
			},
		)
	}
	return &id, nil
}
