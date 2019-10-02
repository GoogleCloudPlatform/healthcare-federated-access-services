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

// Package testkeys provides private/public RSA keys for testing.
package testkeys

import (
	"crypto/rsa"

	"github.com/dgrijalva/jwt-go"
)

// Key is a pair of RSA private/public keys.
type Key struct {
	ID         string
	Private    *rsa.PrivateKey
	Public     *rsa.PublicKey
	PrivateStr string
	PublicStr  string
}

// Component identifies a component in the GA4GH Passport ecosystem.
type Component string

const (
	// Unknown is an unkown component.
	Unknown Component = "testkeys-unknown"
	// VisaIssuer0 is a Visa Issuer.
	VisaIssuer0 Component = "testkeys-visa-issuer-0"
	// VisaIssuer1 is a Visa Issuer.
	VisaIssuer1 Component = "testkeys-visa-issuer-1"
	// PassportBroker0 is a Passport Broker.
	PassportBroker0 Component = "testkeys-passport-broker-0"
	// PassportBroker1 is a Passport Broker.
	PassportBroker1 Component = "testkeys-passport-broker-1"
	// PersonaBroker is a Passport Broker/Visa Issuer for Personas.
	PersonaBroker Component = "testkeys-persona-broker"
)

// Keys contains fake keys.
var Keys = map[Component]Key{
	Unknown:         keyFromPEM(pems[0], Unknown),
	VisaIssuer0:     keyFromPEM(pems[1], VisaIssuer0),
	VisaIssuer1:     keyFromPEM(pems[2], VisaIssuer1),
	PassportBroker0: keyFromPEM(pems[3], PassportBroker0),
	PassportBroker1: keyFromPEM(pems[4], PassportBroker1),
	PersonaBroker:   keyFromPEM(pems[5], PersonaBroker),
}

var (
	// Default is a fake RSA private/public key pair.
	Default = Keys[Unknown]
)

type pem struct {
	Private []byte
	Public  []byte
}

func keyFromPEM(in pem, id Component) Key {
	private, _ := jwt.ParseRSAPrivateKeyFromPEM(in.Private)
	public, _ := jwt.ParseRSAPublicKeyFromPEM(in.Public)
	return Key{
		ID:         string(id),
		Private:    private,
		Public:     public,
		PrivateStr: string(in.Private),
		PublicStr:  string(in.Public),
	}
}

var pems = []pem{
	{
		Private: []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgFPmZrJ9Up2nBGIuXl6wTU+4RsUbpz0nRhPiFk3veAofJ9YZLXbU
IJSifyUr8shM1Jtld8ZMMA2qzXvCV5zBVqR22Neuzwq0O7b6Yim4N4abULp7m6g/
DUpEsvsDjM3tI7w6VoT4kGjTm2G0R50ojzVz48w9vxClFp9BX/VhvzFlAgMBAAEC
gYAmuiRPYW/AG7b3RuYCmSimkq4AD9qrbLR5OxQGl3H2Yhk2R1roDdSYJ0W/N8ES
WfyNWlHmM4a+2EePR86/KbM/IdubHftceTBdSMgqoYWO5fRIe4XGVDbDi8RfqpFc
ncsoqvwhcqks3l0z3jNLNec8IqineCCtc1tTFdygzIJjBQJBAJOi1FpeWoV4sqWA
h6W8WbZcecPhhKYLihBtMqi2LhcRzvZPwlQe+elNT2aOgSVq6gDkmBW3czkb9Ps0
eLzQMwsCQQCRe2oYBarN5qph0RgEYYfE5YHjp2d+Ht9VVhyVOJxFrP+v/A9djBXz
28qhiwcIMKzR6haxEhqDvmzTesiepPNPAkB15wnTiZqdEQEKbxTlZP/4RO3xYv6+
ZGTELZDRb3xrbAtuZc/5wisvCFCqxI+axEFQqT5TyYe5SfxhSUxK7bJ1AkBG7tex
0sGPFxKoEt0U9cDO/eAw8aSCV+cooo3ZK/r19f3M/qc3Q2BIwDeyQCkzkxgQWYSq
3VrUNXq2Oj2rLF39AkEAjoKP8Kh6HuHJnyDyd5vnxsIfMqq+iJVGrrar2vPrgbt0
qKOf8WfauM6oiFVk02YuO5UQL/HfBBV93pq8FKXdng==
-----END RSA PRIVATE KEY-----`),
		Public: []byte(`-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgFPmZrJ9Up2nBGIuXl6wTU+4RsUb
pz0nRhPiFk3veAofJ9YZLXbUIJSifyUr8shM1Jtld8ZMMA2qzXvCV5zBVqR22Neu
zwq0O7b6Yim4N4abULp7m6g/DUpEsvsDjM3tI7w6VoT4kGjTm2G0R50ojzVz48w9
vxClFp9BX/VhvzFlAgMBAAE=
-----END PUBLIC KEY-----`),
	},
	{
		Private: []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICWgIBAAKBgGZ6ZXv/dpmssWUkNkhJfVJgL+c1JLcpv4Y9umEc+/sht1G1Du80
8uXfzsYkHxrZ+kVC5fSop0+bb5Uetq2Cv/Uj8QyapO/oumOa3VfcUsAdtHKCFOqH
zScwbyVAvpTQe9FB4ija4jLNGt0p3XKnpswdDZvihOynypKA3RXetuvxAgMBAAEC
gYBV7NTBBq/EJNfNbXKSZARPmNUxsQ6rAbdUcNeg6/OgW2HhgcYW7jeoZWN0If9u
vUyq3HACF5PKHROPXmRf0hzu9ffpyL+zVJtAwzEwP3TCXRQGnSenYgm34PyMD0P8
g+DtddAjuKhBSRwcG2KF+z51ikiyukrD59o29XU9hr9zvQJBALkuLKBiJXjkKXLu
20A8sX/LPr5zwilc/BO+PB91zS6XujcJBxC6hpcqvcAEyoibwFMdAqwocZVLVCJQ
U1ts7Z8CQQCNq195Q5ZIBVkhLAtybZXkY/qZ5BnD7DdEmtLVmVID0cGngz3lgs09
OOshmws0F/+MBlAHaJs+CWJYZkF58ZxvAkBduvVzqLn22uXv+t6XQSFG4gU8OTOJ
5Drjc2LTOblFYB8tRDCDUyZU1Zl92+73/n32k7SKl14Ghz5qr+XBXP1ZAkBsMink
bx3jO1Jq5zyG0/LaTxEhXvfejhVXq/bBcysUB6qiyLUJB/C/hSzuqX7Q9lMRGfEc
92M46enWIaJ4A3K5AkAnYoE64xC8UoJtCeXJ/uY/YiNczIX2zbB8qjCJIxWPIwby
gW8okA8HOWitOMGS/QbdoYlbyyzbw77GwGqMaWyx
-----END RSA PRIVATE KEY-----`),
		Public: []byte(`-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgGZ6ZXv/dpmssWUkNkhJfVJgL+c1
JLcpv4Y9umEc+/sht1G1Du808uXfzsYkHxrZ+kVC5fSop0+bb5Uetq2Cv/Uj8Qya
pO/oumOa3VfcUsAdtHKCFOqHzScwbyVAvpTQe9FB4ija4jLNGt0p3XKnpswdDZvi
hOynypKA3RXetuvxAgMBAAE=
-----END PUBLIC KEY-----`),
	},
	{
		Private: []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDwLljNK1EwQT1/71Xfmy6z1LbmC7J5m7TEdv2QeeZZW4mC0LXc
G7KvxXOnfzu45zBq5p2Fv6dw7CbQbNaj7bbF9doEnD2sQLA5rB0IrAss+YIv3PN3
437g3UU8L2Sw1UaoRIfuLx9u9TuK1EgeWjSjNgmOrlPp7r8jGizVnec6FQIDAQAB
AoGASVYtgUAnwy84gxbmRqeQpBJgYm/R6DX2BUM7+2BtSH2dyFbIINRIRElrHgrI
hpX4/7s4//zcOKuy0lNZWqab9tDEEtPl8TNq6qgFaBLVngZa4Z5LfFv/pA3bIBKD
ina9osJ0zhlbQUpMOh4jA/V9pQvfb0HF94vC3+YbFK5Qt2ECQQD4fI4vdl027pDw
JfTT3TqNnxQ5zS7/5u5ZzvDHRVmmqO4PFyk+9p6mIBHhTEuQBkZPjb2ATtEZlMR9
xUx8hQ15AkEA93GAZ16837eg5JhEhMKxSvWRjDxrxO3GTrbjHD1Qk8tdw/+BjjZD
fWK5VNxnFE8A8BkKfVVbIRlihp5HjHFWfQJAESz63wj9dHiVCCR3gdV+4J8oVL58
CzA5NXf6aKvAgKaYne5p6XI+kRkSY1JUvsXQQlt3x9Cq32vLES58FPdVcQJBAIrj
6MEdCkNA3Uyys3MZnU6H/ISMvakyFefE/EGzoPD0a9NCLcRXbRaKPaEGfc2Gcu5R
//NN3/L6PrV1To/kZjkCQQD1zGnD59U8YT6ShQ4BtMht8u4rsQRDnK0B5ZoYC2W5
hN0gaHOqt3ZqJrZVR8goLGp9cOCTpyj+Vfvrdr8MiJrg
-----END RSA PRIVATE KEY-----`),
		Public: []byte(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwLljNK1EwQT1/71Xfmy6z1Lbm
C7J5m7TEdv2QeeZZW4mC0LXcG7KvxXOnfzu45zBq5p2Fv6dw7CbQbNaj7bbF9doE
nD2sQLA5rB0IrAss+YIv3PN3437g3UU8L2Sw1UaoRIfuLx9u9TuK1EgeWjSjNgmO
rlPp7r8jGizVnec6FQIDAQAB
-----END PUBLIC KEY-----`),
	},
	{
		Private: []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCOP7hFgzGGIKSBLnmH2BCNt8CvwGL8thrQ+NKCuTrl+I24V4uF
2fmQRRjfVAPiha4q8CbDJfXTnQVPhXsqWrq5pZMRHhIyCzgWYIvD6WJ+Dqf7l7lP
xKet5Dd38L/EiNe/HMc6InBmkQ9J0A6ndpmEAABO3wpoXEzVWx7cOWMkvQIDAQAB
AoGAEK4uKJCSzRykzbUqcSCICGZExRc1RFcCXADhhoy7+F2mGLjDVqXR2vYPTZjn
f7eXTdetY/Lembru9X08jSHohU/nFlfv0NuTPJZvxXh42sB265bl4YUaQwXIBLxj
qFDxlSjJY2Ukfv6QuhleQkzMPVkokvM/YQN8dSE6AUci3Y0CQQD+K8odxNe4avM8
v2AY3xAYatEsN+ku9YcCEC1QUqG6RBMWJcpfTuRupnBv75OnGk7aiV4SAjh6nGEc
JW3TJeJnAkEAj0XB9CNaiylWpojeywGSwrd7+RB1149v3iebfmbqn5xc5gARo58n
wgPTeeSGzOn3cJ5HLxcrJ+T/1RJ2/TPxOwJBAPYrjzw50/0HiMIDUJ2GHd6oRiMf
m7chkjsLU/gBsCXpnNrMiy64CEKq7Sdc0JL9xfWfKf8jK3SFVQCft7jTbm0CQGdq
yQe7BT5yRnPLVFZg+ljHLRupQAarKOrI2DqzeyRfL8dtwU3EMmSfcmUICi2brNqD
xYo+RQ51BB3/SBiZB8UCQGLzyWH5il98LpDW8BmKZjkxDmz3yWzA9BEhVLF7HrmA
uH5IhS4AE1o6JekYR9PNIYqvNxRL2cIAiZW4S9AUn2s=
-----END RSA PRIVATE KEY-----`),
		Public: []byte(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCOP7hFgzGGIKSBLnmH2BCNt8Cv
wGL8thrQ+NKCuTrl+I24V4uF2fmQRRjfVAPiha4q8CbDJfXTnQVPhXsqWrq5pZMR
HhIyCzgWYIvD6WJ+Dqf7l7lPxKet5Dd38L/EiNe/HMc6InBmkQ9J0A6ndpmEAABO
3wpoXEzVWx7cOWMkvQIDAQAB
-----END PUBLIC KEY-----`),
	},
	{
		Private: []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCYCwIr2VWKLmOriOmL0FUNUvig2ib+6r6/C7z019oH/vC+XhRL
mT0Y9TRK6qlYEs8iYoVRGW8fkNRhNk6uWbJJDx406eNGNA0DH+mMOvkhVsDjsgIM
WJi8kk0X7WpRpGCBAGd/AhYUWYpUEvWWgQanwIdLTjnruG6yRP4OmINihQIDAQAB
AoGACFvak7SQGlewjRaq2E/szR25o4Y6zJr1P6WSjtdrGjNu4thjP0C+difM5y19
f+UQ1DAcajf+vvqEYo/MxZMS1RGhcDF8cuwFXbbkdu264jZ3+cinvltlu7koiNXg
S+DP9i4Br3TF+XDAf/osWAsBAIF0vm5soWXj6f3WVRt8BIUCQQDYdJy/9urSArNI
S6VKKV4QUX8Duw46vVrPMKGgZ4o+eWZ/9W9XvatnSTmQFEmhVXFO++GQs5XQ35oS
1cqtMh+zAkEAs9HksSkTzOHCkpzZWx5Zqr882MzIUgCs8Vj/r58cTB9OXzPtz+a2
Mvyg9vTAzkgFB6jWJ1EPK78iTY9vxXAY5wJBAJBUOUza5LrB6C91mTI5ISp6XNns
+VD7f7iVccAWKhz8L/d0fRihNNA7CDHlBS+ZXGNRGpe011meLwsOGQWhXXcCQHvN
ebdjgadgk7afWKJ8Xd3J9pmJPC4BGxC7ZqZCVJgwQaQYO5YU0MJ/3k7Iqeob+aKR
YogFLf2/hV2C8MAtcmcCQQClYiiihHONOv09CfxVN/vJCZxj4Id8TxRFYsMj3/qP
pKzQY34zsRspXN9cGait5la41EmRdk23H6ddTLlmOtGt
-----END RSA PRIVATE KEY-----`),
		Public: []byte(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCYCwIr2VWKLmOriOmL0FUNUvig
2ib+6r6/C7z019oH/vC+XhRLmT0Y9TRK6qlYEs8iYoVRGW8fkNRhNk6uWbJJDx40
6eNGNA0DH+mMOvkhVsDjsgIMWJi8kk0X7WpRpGCBAGd/AhYUWYpUEvWWgQanwIdL
TjnruG6yRP4OmINihQIDAQAB
-----END PUBLIC KEY-----`),
	},
	{
		Private: []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICWgIBAAKBgGmT42puFENUNvSBdJXRVV11p6UsuUjgtlKGDVouVxEi6aEgPRmb
7/P+KJPQaYwohscxl0vXYDQz2vZMznjM4nJML4pm2/FrOqkfChUzlU3Vb1RDkuqD
0QTTnLt4aOw8GuOO0oqkC+5vLXlwVNBboLGTHXwGFuIoWKw0eND8MonTAgMBAAEC
gYBDKTqvx5rIQdg7reZWL7YYH/InVs3/GEOjN3di+LuWQRlR0EpN8i6wjeuOLDQY
Xudt65QNQNMIIjyWFcH6gotBzDsccrgRpHYwyaC644ozBnmGHs5kb3M0lhxuCJ+f
rpw3qiBpGacYmzZbxPm46rj4/oCFC2jh+OW2m+YqiWP2sQJBALRJaavOcNTVUL/j
9BMNj/97m2MRcatGOPmaLpi4BrXYR6nyTnq94MepSmpY5xRHewFL4RFFR12boIon
HByvHGcCQQCV6oU0HeuA8RjBrvAciD3Zm8LY42gIsttqfbqjmgCwWSSkaW6i6U9I
ZKPFlb7IhaK+tZH91WQa/13dgItHl8O1AkBYLjwwW4YWo8ueP+nm09Bl3tiO6T5W
zr8ZXs+BxSkLEqFiv3ChWnQyVFxgjeFgquHALZQFNYSFhZRNXnnCkefrAkBh1iWM
N6KECdQQQqys0jUbGM32YaJ5WtBbFSaCsnSUofiJ28y6QOze398JiYpyrtPhBfn6
4BJulA2cCtHarS6pAkB+rBcsL5EmymwUk0KUlMYBNMRh2rkz4hSeML0i5/NCr1ck
d2T5FipnEC+9V0Xtmvb4/zuMv0gzI0WG+2hJOaGo
-----END RSA PRIVATE KEY-----`),
		Public: []byte(`-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgGmT42puFENUNvSBdJXRVV11p6Us
uUjgtlKGDVouVxEi6aEgPRmb7/P+KJPQaYwohscxl0vXYDQz2vZMznjM4nJML4pm
2/FrOqkfChUzlU3Vb1RDkuqD0QTTnLt4aOw8GuOO0oqkC+5vLXlwVNBboLGTHXwG
FuIoWKw0eND8MonTAgMBAAE=
-----END PUBLIC KEY-----`),
	},
	{
		Private: []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgHswVrcmyu7d1NKn54T6mfY6m//asi9pDJm+grG+C+eMQ9j40j97
0URKipEmKrfIH/iyAi17JtY7SlTuGCSqgyTMNFS8ZdUZqmHM1gRr/qTSS2FiUaKP
sLJl2/F35i2ZZMm0rWOkmffRwEEuNuHqLBfAB+nGFU4nz1Tt5twdElFVAgMBAAEC
gYAKEU1E8pqrIt39yVMWfxSOFwQgyNK/JSqude9gb1OxvLjexpcIMSpNFnp0mlXr
ZyOVw5aB+QqXf4j3n+3BMV4+Sna9Rmio/cSSSfWWwbq54NH+28pNRRFGOrKh4OxI
bbkRHIQ0EQ3lhGaVwnM3ER0VnbTAx46jSSxDFV65dBZrgQJBAMQUWkSdQed5FoQ3
2IIx2J1jgp8TT5ZkIbMMvoTeNzY3sVjpMVrpsycKVYuiWLFs4+cBdgo6WZbVJajN
7ptqoRkCQQCg1Z5zrRKaH7O+A0aFWw9Vy8ftDtvk6V9fmgV3zZXu3NolmPXP/97Y
ZkiAsYYlnvPblq4H+cq0j0xxjsFmIU2dAkAvFJP4FapVYgW+CYq6+C0C3XnnqENb
4P8WduDoFlM7eXPj3Vo0chjKLvkLZhfVwkeWmAs3uXr5dIRuW8QHHTtBAkBqlOWK
NrlLFZMhaj5DhVKmQoLcn6otClI/omvZNo4TWpvdqn3LNv7QXQfS8NG7AJkNfc8a
Tfh8qzG3Vyjmq08pAkEAoZnOJYOjj04SVb9gf9xquz9gP/m5UQvrgJzkD+K8NWTD
d2mZMaqRL8iuCnjKxYPEb2jjGqbEt0vVXXHw+zwwDA==
-----END RSA PRIVATE KEY-----`),
		Public: []byte(`-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgHswVrcmyu7d1NKn54T6mfY6m//a
si9pDJm+grG+C+eMQ9j40j970URKipEmKrfIH/iyAi17JtY7SlTuGCSqgyTMNFS8
ZdUZqmHM1gRr/qTSS2FiUaKPsLJl2/F35i2ZZMm0rWOkmffRwEEuNuHqLBfAB+nG
FU4nz1Tt5twdElFVAgMBAAE=
-----END PUBLIC KEY-----`),
	},
	{
		Private: []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICWgIBAAKBgEXBhVYMfFNEjiLbRUXW5AU2dyZJ5kkL8T1XRTUIHjLI/e6Wfqve
TaD3ziVFXIijFIoesVrl/apDQDNdQDxaX+q5UAnzlu9tryYxzGZhKWz+sxgjzaZx
pYq5kQF5wglHgmYnYA2K/09gZ4UsbIrtYc+wib+E4v3UL5atzMY4e90rAgMBAAEC
gYArFf1lyRCB3jZtEUMYgEMXdSzjWYIEXHwFh4IX34vHkp5GYG6dehI4+tc57j3Z
p+Fn7s1dd/HW2PMuxsqGfMwBapik/wBpthTFGTbpmSpmPvfFkRUBwi6/NE2WAdPh
wTtmhdcOSDYH91N606rwLVgJLC6fEVzrM8KRp1bETHi0AQJBAIgmu9HH5B1ppzvZ
ia6K/47J45yGCT+16LGl1xyzA2esQdDGFF3lfajQhJHHK/orFSlnHUbkhEFpXeOC
H0Ap7XsCQQCDKM1GM5FX+KAPrNLh2OqlWX4ivENl11buipGtij6bc/FVMz5kUi22
M7m6lY/FOTeRGne+hn2D6gHihd+dEcgRAkAjZ38btBEbnOfB5nWpD7gY12L6xtgM
2y7hUzC2484U3XRX58pQCGc+yMpQZiyHZ0CffZLdZnsFz3J8wM+DjeOVAkAd4zBT
rPCT0U34BHPRjzJ5F1mM5MWe8WEX3m+v0e7OUa9OsOyow6ky+bp68BXg5VbqM9PR
kKgNZUekrMj169VhAkBOQmONQQOEKPLomlFuRZavTmmf3t+D8NXL4ZWviIUn77Ov
t5AtQckM9uwoBXdM2dLl4CNIUPG0KJlu8Zy4Ju1o
-----END RSA PRIVATE KEY-----`),
		Public: []byte(`-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgEXBhVYMfFNEjiLbRUXW5AU2dyZJ
5kkL8T1XRTUIHjLI/e6WfqveTaD3ziVFXIijFIoesVrl/apDQDNdQDxaX+q5UAnz
lu9tryYxzGZhKWz+sxgjzaZxpYq5kQF5wglHgmYnYA2K/09gZ4UsbIrtYc+wib+E
4v3UL5atzMY4e90rAgMBAAE=
-----END PUBLIC KEY-----`),
	},
	{
		Private: []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCxAlaaehxobau/ewj+Ghe0vXpOnYJKcUsUVoTTminpqfi9kXQ2
daFaDuXbMG2URqNVd7vKUYjnSmDKmcMQZt/84U0GgKex2izt7SAuO5QQzeBeabom
BWbIeE1/msTFeZ1iOO/FIoUyiTuEsZNMw6CAdi0b7ybWjEDuvr7QzWJV3QIDAQAB
AoGBAJ6Y2b/PaWSn3xrRwlzqRBNNMij+N587o2m1m418s9EI2jX//YBOJSPr9UdP
PN996xrJDRlZtLCHk/HzkzM++bC3aY7rc/TsR72yWg50jhUJ02Li9UR9ZwSng54a
UovDS5fL1PFK1wPOsIZM8WhUVcq40kGHcMOucwqALxn10caBAkEA/WBxyvjqOn99
pcIoS6OwXnPRjjqcCgDNkWaT2o68CaA/hco8olAL/vjSUvoqlIgym2io1vhFo41k
YNVIMud61wJBALLXfMMQJ+JgqjN0D+sSPFZqQz0MsK8tDR1GUijpAEYsc1+qFG4J
AG3Z+RyldQcQWy8LWFYLXHTy6JdrBiP8MmsCQAplZ6XdWrb1vjEL611XJQhrFiEQ
1JAwgj7CB7UDAEIg2hpiNuSuBh/7E54l95NKl1D7FVpkq27PgVvbxG+aQdcCQBwj
2/W1bREptJ4z/O04CVZvkfThMkveAtpAXl0hjHF+PQkocd5+fBrM2W2weyGJaU+V
sWiYkQu1zPNGW8j9vdECQQCvPaTzxOoyT3U76EpmSdTsU0gYGXbhpnlk8TFrQDZa
Dq7OeI/9BspyLxrJk7JeMoqUUQA103nbi+MoDuE9cBG0
-----END RSA PRIVATE KEY-----`),
		Public: []byte(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCxAlaaehxobau/ewj+Ghe0vXpO
nYJKcUsUVoTTminpqfi9kXQ2daFaDuXbMG2URqNVd7vKUYjnSmDKmcMQZt/84U0G
gKex2izt7SAuO5QQzeBeabomBWbIeE1/msTFeZ1iOO/FIoUyiTuEsZNMw6CAdi0b
7ybWjEDuvr7QzWJV3QIDAQAB
-----END PUBLIC KEY-----`),
	},
}
