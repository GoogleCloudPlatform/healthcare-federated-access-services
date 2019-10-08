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

// Package fakeissuer provides a minimal fake OIDC issuer for testing purpose.
//
// Example:
//
//   // Create a fake HTTP server and client.
//   f, cleanup := fakehttp.New()
//   defer cleanup()
//
//   // Set the URL of the issuer to that of the fake HTTP server.
// 	 issuer = testkeys.Keys[testkeys.VisaIssuer0]
//   issuer.ID = f.Server.URL
//   i := stubissuer.New(f.Server.URL, issuer)
//   f.Handler = i.Handler
//
//   // Override the context to tell the package to use the fake HTTP client.
//   // Any HTTP calls to issuer by oidc using ctx will be handled by the fake.
//   ctx := oidc.ClientContext(context.Background(), f.Client)
//
package fakeissuer

import (
	"net/http"

	glog "github.com/golang/glog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/square/go-jose.v2"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys"
)

const (
	// OIDC URI.
	OIDC = "/oidc"

	// WellKnown URI.
	// https://www.iana.org/assignments/well-known-uris/well-known-uris.xhtml
	WellKnown = "/.well-known"

	// Configuration URI.
	Configuration = WellKnown + "/openid-configuration"

	// JWKS URI.
	JWKS = WellKnown + "/jwks"

	// Authorize URI.
	Authorize = "/authorize"

	// Token URI.
	Token = "/token"

	// UserInfo URI.
	UserInfo = "/userinfo"
)

// GetWellKnownResp is the type for GET WellKnown Response.
type GetWellKnownResp struct {
	Issuer      string `json:"issuer"`
	AuthURL     string `json:"authorization_endpoint"`
	TokenURL    string `json:"token_endpoint"`
	JWKSURL     string `json:"jwks_uri"`
	UserInfoURL string `json:"userinfo_endpoint"`
}

// GetJWKSResp is the type for GET JWKS Response
type GetJWKSResp = jose.JSONWebKeySet

// Issuer is a fake OIDC issuer.
type Issuer struct {
	URL              string
	Keys             []testkeys.Key
	GetWellKnownResp GetWellKnownResp
	GetJWKSResp      GetJWKSResp
}

// New creates a new Issuer.
func New(url string, keys ...testkeys.Key) *Issuer {
	i := &Issuer{
		URL:  url,
		Keys: keys,
		GetWellKnownResp: GetWellKnownResp{
			Issuer:      url,
			JWKSURL:     url + JWKS,
			AuthURL:     url + Authorize,
			TokenURL:    url + Token,
			UserInfoURL: url + UserInfo,
		},
	}

	for _, key := range keys {
		k := jose.JSONWebKey{
			KeyID:     key.ID,
			Key:       key.Public,
			Algorithm: ga4gh.RS256.Name,
			Use:       "sig",
		}
		i.GetJWKSResp.Keys = append(i.GetJWKSResp.Keys, k)
	}

	return i
}

// Handler is the HTTP handler for the issuer.
func (i *Issuer) Handler(req *http.Request) (body interface{}, err error) {
	url := "http://" + req.Host + req.URL.Path
	switch {
	case req.Method == "GET" && url == i.URL+Configuration:
		return i.GetWellKnownResp, nil

	case req.Method == "GET" && url == i.URL+JWKS:
		return i.GetJWKSResp, nil
	}
	glog.Infof("Server: %q", i.URL+Configuration)
	glog.Infof("Unkown Method and URL: Method=%v URL=%v\n", req.Method, url)
	return nil, status.Errorf(codes.NotFound, "Cannot handle %q on %q", req.Method, url)
}
