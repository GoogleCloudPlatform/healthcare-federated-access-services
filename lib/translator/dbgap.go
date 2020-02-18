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
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"path"
	"regexp"
	"strings"
	"time"

	"gopkg.in/square/go-jose.v2/jwt" /* copybara-comment */
	"github.com/coreos/go-oidc" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common" /* copybara-comment: common */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
)

const (
	// TODO: Update the issuer address once NCBI stands up their own OIDC endpoint.
	dbGapIssuer         = "https://dbgap.nlm.nih.gov/aa"
	dbGapOrgURL         = "https://orgs.nih.gov/orgs/"
	dbGapUserInfoURL    = "https://dbgap.ncbi.nlm.nih.gov/aa/jwt/user_info.cgi?${TOKEN}"
	dbGapPassportURL    = "https://dbgap.ncbi.nlm.nih.gov/aa/jwt/user_passport.cgi?${TOKEN}"
	eraCommonsAuthority = "eRA"
	visaScope           = "openid"
	fixedKeyID          = "kid"
)

// DbGapTranslator is a ga4gh.Translator that converts dbGap identities into GA4GH identities.
type DbGapTranslator struct {
	publicKey *rsa.PublicKey

	visaIssuer        string
	visaJKU           string
	signingPrivateKey *rsa.PrivateKey
}

type dbGapStudy struct {
	Accession *string `json:"accession"`
}

type dbGapAccess struct {
	Study   dbGapStudy `json:"study"`
	Expires int64      `json:"expires"`
	Issued  int64      `json:"issued"`
}

type dbGapPassport struct {
	Access []dbGapAccess `json:"access"`
	Org    *string       `json:"org"`
	OrgID  *string       `json:"org_DUNS"`
	Role   *string       `json:"role"`
	SO     *string       `json:"so"`
}

type dbGapIdentity struct {
	Authority string      `json:"authority"`
	ID        interface{} `json:"id"`
}

type vCard struct {
	Email      string   `json:"email"`
	GivenName  string   `json:"fname"`
	FamilyName string   `json:"lname"`
	Orgs       []string `json:"orgs"`
	Roles      []string `json:"roles"`
}

type dbGapClaims struct {
	DbGapPassport []dbGapPassport `json:"dbgap_passport"`
	Identity      []dbGapIdentity `json:"identity"`
	Vcard         vCard           `json:"vcard"`
}

// dbGapIdToken mocks OIDC library's idToken implementation, except minor differences in the types of
// Audience, Expiry, and IssuedAt fields to facilitate JSON unmarshalling.
type dbGapIdToken struct {
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

func convertToOIDCIDToken(token dbGapIdToken) *oidc.IDToken {
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
func NewDbGapTranslator(publicKey, selfIssuer, signingPrivateKey string) (*DbGapTranslator, error) {
	if len(selfIssuer) == 0 || len(signingPrivateKey) == 0 {
		return nil, fmt.Errorf("NewDbGapTranslator failed, selfIssuer or signingPrivateKey is empty")
	}

	t := &DbGapTranslator{
		visaIssuer: selfIssuer,
		visaJKU:    path.Join(selfIssuer, ".well-known/jwks.json"),
	}

	block, _ := pem.Decode([]byte(signingPrivateKey))
	if block == nil {
		return nil, fmt.Errorf("decode private key failed")
	}
	pri, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %v", err)
	}
	t.signingPrivateKey = pri

	block, _ = pem.Decode([]byte(publicKey))
	if block == nil {
		return t, nil
	}
	pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %v", err)
	}
	t.publicKey = pub

	return t, nil
}

// TranslateToken implements the ga4gh.Translator interface.
func (s *DbGapTranslator) TranslateToken(ctx context.Context, auth string) (*ga4gh.Identity, error) {
	if err := common.VerifyTokenWithKey(s.publicKey, auth); err != nil {
		return nil, fmt.Errorf("verifying user token signature: %v", err)
	}
	userInfo, err := s.getURL(dbGapUserInfoURL, auth)
	if err != nil {
		return nil, fmt.Errorf("getting dbGaP user info: %v", err)
	}
	if err := common.VerifyTokenWithKey(s.publicKey, userInfo); err != nil {
		return nil, fmt.Errorf("verifying user info token signature: %v", err)
	}
	passport, err := s.getURL(dbGapPassportURL, auth)
	if err != nil {
		return nil, fmt.Errorf("getting dbGaP passport: %v", err)
	}
	if err := common.VerifyTokenWithKey(s.publicKey, passport); err != nil {
		return nil, fmt.Errorf("verifying passport token signature: %v", err)
	}

	var claims dbGapClaims
	var id dbGapIdToken
	if err := s.extractClaims(auth, &id, &claims); err != nil {
		return nil, fmt.Errorf("extracting user claims: %v", err)
	}
	if err := s.extractClaims(userInfo, &id, &claims); err != nil {
		return nil, fmt.Errorf("extracting user info claims: %v", err)
	}
	if err := s.extractClaims(passport, &id, &claims); err != nil {
		return nil, fmt.Errorf("extracting passport claims: %v", err)
	}
	return s.translateToken(convertToOIDCIDToken(id), claims, time.Now())
}

func (s *DbGapTranslator) getURL(url, userTok string) (string, error) {
	url = strings.Replace(url, "${TOKEN}", userTok, -1)
	get, err := http.Get(url)
	if err != nil {
		return "", err
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(get.Body)
	body := buf.String()
	if get.StatusCode < 200 || get.StatusCode > 299 {
		return "", fmt.Errorf("http status %d: %v", get.StatusCode, body)
	}
	return body, nil
}

func (s *DbGapTranslator) extractClaims(tok string, id *dbGapIdToken, claims *dbGapClaims) error {
	parsed, err := jwt.ParseSigned(tok)
	if err != nil {
		return fmt.Errorf("parsing signed token: %v", err)
	}
	err = parsed.UnsafeClaimsWithoutVerification(id, claims)
	if err != nil {
		return fmt.Errorf("extracting claims from token: %v", err)
	}
	return nil
}

func (s *DbGapTranslator) translateToken(token *oidc.IDToken, claims dbGapClaims, now time.Time) (*ga4gh.Identity, error) {
	id := ga4gh.Identity{
		Issuer:     token.Issuer,
		Subject:    token.Subject,
		Expiry:     token.Expiry.Unix(),
		GivenName:  claims.Vcard.GivenName,
		FamilyName: claims.Vcard.FamilyName,
		Name:       common.JoinNonEmpty([]string{claims.Vcard.GivenName, claims.Vcard.FamilyName}, " "),
		Email:      claims.Vcard.Email,
		VisaJWTs:   []string{},
	}
	for _, ident := range claims.Identity {
		if ident.Authority == eraCommonsAuthority {
			if username, ok := ident.ID.(string); ok {
				id.Username = username
			}
		}
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
			// TODO: Verify that the heuristics for de-duplicating access entries is correct.
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
			r = "nih.researcher"
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
	affiliationAsserted := now.Unix()
	for a, val := range accessions {
		visa := ga4gh.VisaData{
			StdClaims: ga4gh.StdClaims{
				Subject:   token.Subject,
				Issuer:    s.visaIssuer,
				ExpiresAt: val.Expires,
				IssuedAt:  val.Issued,
			},
			Assertion: ga4gh.Assertion{
				Type:     ga4gh.ControlledAccessGrants,
				Value:    ga4gh.Value("https://dac.nih.gov/datasets/" + a),
				Source:   dbGapIssuer,
				By:       ga4gh.DAC,
				Asserted: affiliationAsserted,
			},
			Scope: visaScope,
		}
		v, err := ga4gh.NewVisaFromData(&visa, s.visaJKU, ga4gh.RS256, s.signingPrivateKey, fixedKeyID)
		if err != nil {
			return nil, fmt.Errorf("sign ControlledAccessGrants claim failed: %s", err)
		}

		id.VisaJWTs = append(id.VisaJWTs, string(v.JWT()))

		// Keep the oldest Issued accession for use as affiliationAsserted.
		if val.Issued > 0 && val.Issued < affiliationAsserted {
			affiliationAsserted = val.Issued
		}
	}

	for a, src := range affiliations {
		// Claim for dbGap
		visa := ga4gh.VisaData{
			StdClaims: ga4gh.StdClaims{
				Issuer:    s.visaIssuer,
				ExpiresAt: currUnixTime + validSec,
				IssuedAt:  affiliationAsserted,
			},
			Assertion: ga4gh.Assertion{
				Type:     ga4gh.AffiliationAndRole,
				Value:    ga4gh.Value(a),
				Source:   dbGapIssuer,
				By:       ga4gh.System,
				Asserted: affiliationAsserted,
			},
			Scope: visaScope,
		}
		v, err := ga4gh.NewVisaFromData(&visa, s.visaJKU, ga4gh.RS256, s.signingPrivateKey, fixedKeyID)
		if err != nil {
			return nil, fmt.Errorf("sign dbGap ClaimAffiliationAndRole claim failed: %s", err)
		}

		id.VisaJWTs = append(id.VisaJWTs, string(v.JWT()))

		// Claim for org
		visa = ga4gh.VisaData{
			StdClaims: ga4gh.StdClaims{
				Issuer:    s.visaIssuer,
				ExpiresAt: currUnixTime + validSec,
				IssuedAt:  affiliationAsserted,
			},
			Assertion: ga4gh.Assertion{
				Type:     ga4gh.AffiliationAndRole,
				Value:    ga4gh.Value(a),
				Source:   ga4gh.Source(dbGapOrgURL + src.orgID),
				By:       ga4gh.By(src.by),
				Asserted: affiliationAsserted,
			},
			Scope: visaScope,
		}
		v, err = ga4gh.NewVisaFromData(&visa, s.visaJKU, ga4gh.RS256, s.signingPrivateKey, fixedKeyID)
		if err != nil {
			return nil, fmt.Errorf("sign org ClaimAffiliationAndRole claim failed: %s", err)
		}

		id.VisaJWTs = append(id.VisaJWTs, string(v.JWT()))
	}
	return &id, nil
}
