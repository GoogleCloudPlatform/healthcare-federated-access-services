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
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/coreos/go-oidc"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh"
)

const (
	testPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAmFKS4nx/+qC342ZDlHLiDcXOWmYItYTELnUC+t70ZSYuGhiY
FTR88667C56ixLrcTKVn3OkgBFrpKUlKttufis8v/K37AkmTHjSGR1zyZCQJffRU
uWlBANBycy7I5Zo7VzAwuvgS4tzqO4lW1EE49XN1OVtkSxH6LhQkaWqRf+PCq+Sh
LGQMnx/Zv1l8bX/wNi4MkMdD1Z+mjfkv2ZPF+ScQn0L6z9XuyQm8IUQAAeeJDLIR
WYiy1axoZaM2cXY6aMpKyVLeuHbmBEt/cRns8dld4UWHswJ0Ivaa5mpB6EIDc+Tt
nFekzslxeOFYmPTvnhfhEjOdo85TO4IAv/GXJQIDAQABAoIBAFEv+fBT8ZaxYTII
SM7v6ML0goc2SUAO0s38Oili+pqLHhl0sGLlBhCQOkv4MsNu4YrMwq5BZ3pKxmnm
EbejGcdPpUElrltKwepgjo2s4dk0SAblWt80VZxMfiQcdKHEcgqHugF9xfs7SnGP
Q0OAvA4/iuSWbL+ChnlW7Q1u6rxh48OgpI03cwvHKKH2ol+RAKHreq1yd2syxnME
7D3lOsqpZOVMzpQYWrd6FeUi2EVV80KsSKHVYiXXmwcDNxlj97w/CdbbP8MfwH5k
00H5o+8IO4iBFtF0obFbsCXH9IbuG+CjzLkI+m7zyESljSJ0f9+g/eev5gRvGVua
qWeUPaUCgYEAwAy6VAa+8Jl2umN5pGewKvN0bz4+fTJoc9kaBQTpHD0ujcqaUbj0
faLi32UDUa1VREyOZ/Og8a1N4rksfzXdvmQQL3AluEeo02WWkHec7Rs3fel3GUdX
0W2IrCAl8gceo0O8qwM67+700jh4mjJaG7Ge3aE9lqA4SvAw0237DDsCgYEAywtO
F/TFBjAqcTwO81IdmameohJr5PWAT+X8dzZNzYzyvyBd6IcRwv9gfiCKfFUY7981
iqVV2q6Yx3su/RX6DQuS3F+Q/gb7Szf8Int8cWvo+z9aLFr5yOnZXGTtBGizUD/9
XMcNAyVOLMJMMU7XJBHfShITzmPIPFo1fS/blB8CgYEAgwqsQRVxR96PItMpd0LA
9C22bwl7vhWdLB8hH/ef0AL3Nwzdi5G2UdvJDkFwqFSrb7UFHm0gjoeAM4nCkPKC
YZ0JZjURp9JNoiEZQW48h5UgoiuhdoA1rdMdhMVS3vh4sVJQ9Cd6GallJ+QcdqqQ
zYC/M98HlTWx84A88KeEu20CgYALCSBDeRBEV9XWtbbyTqJBOdDfajTnCtjgftWL
/S2ZYHHJJY81FjJG8O5jrI0aWN20G+OjF31lF1xCa1WQd+NRVjGzPJZ62BJMckyH
60JGP+E31qemBYPSAbPIq8ueE7q7P98bbc4tP5fSIvVVML3MvhPuyLC+5Pl7HkQN
+83pbQKBgHGCtaZW2ZBAX5Che3n/m0R5xleLWt8AZt/GYLfxBllV8H2OzlqxwRHx
VGbsq5JJ9a7Ay7rbwkWBYhleuQrj3oSx7k0pxKsyIg5+YpnLYovDObKGPZMAz1ng
KOV2inr376FuOvliDsieIvocO1F/3apaPmpOysK3TR1t6QmwYSBj
-----END RSA PRIVATE KEY-----`
)

func (s *ElixirTranslator) TestTranslator(_ *oidc.IDToken, payload []byte) (*ga4gh.Identity, error) {
	var claims ga4gh.Identity
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	jot := jwt.NewWithClaims(jwt.SigningMethodRS256, &claims)
	block, _ := pem.Decode([]byte(testPrivateKey))
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing Elixir test private key: %v", err)
	}
	token, err := jot.SignedString(priv)
	if err != nil {
		return nil, fmt.Errorf("signing Elixir test passport: %v", err)
	}
	return s.translateToken(token)
}

func TestElixir(t *testing.T) {
	translator := &ElixirTranslator{
		verifier: nil,
	}
	tests := []testCase{
		{
			name:       "successful translation",
			input:      "testdata/passports/elixir.json",
			translator: translator,
			expected:   "testdata/passports/elixir_to_ga4gh.json",
		},
		{
			name:       "translation of passport with no claim",
			input:      "testdata/passports/elixir_no_claim.json",
			translator: translator,
			expected:   "testdata/passports/elixir_no_claim_to_ga4gh.json",
		},
	}
	testTranslator(t, tests)
}
