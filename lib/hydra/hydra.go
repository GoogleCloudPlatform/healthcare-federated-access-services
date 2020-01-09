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

// Package hydra contains helpers for using hydra
package hydra

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/apis/hydraapi" /* copybara-comment: hydraapi */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common" /* copybara-comment: common */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */
)

// GetLoginRequest fetches information on a login request.
func GetLoginRequest(client *http.Client, hydraAdminURL, challenge string) (*hydraapi.LoginRequest, error) {
	u := getURL(hydraAdminURL, "login", url.QueryEscape(challenge))
	resp := &hydraapi.LoginRequest{}
	err := httpGet(client, u, resp)
	return resp, err
}

// AcceptLogin tells hydra to accept a login request.
func AcceptLogin(client *http.Client, hydraAdminURL, challenge string, r *hydraapi.HandledLoginRequest) (*hydraapi.RequestHandlerResponse, error) {
	u := putURL(hydraAdminURL, "login", "accept", url.QueryEscape(challenge))
	resp := &hydraapi.RequestHandlerResponse{}
	err := httpPut(client, u, r, resp)
	return resp, err
}

// RejectLogin tells hydra to reject a login request.
func RejectLogin(client *http.Client, hydraAdminURL, challenge string, r *hydraapi.RequestDeniedError) (*hydraapi.RequestHandlerResponse, error) {
	u := putURL(hydraAdminURL, "login", "reject", url.QueryEscape(challenge))
	resp := &hydraapi.RequestHandlerResponse{}
	err := httpPut(client, u, r, resp)
	return resp, err
}

// GetConsentRequest fetches information on a consent request.
func GetConsentRequest(client *http.Client, hydraAdminURL, challenge string) (*hydraapi.ConsentRequest, error) {
	u := getURL(hydraAdminURL, "consent", url.QueryEscape(challenge))
	resp := &hydraapi.ConsentRequest{}
	err := httpGet(client, u, resp)
	return resp, err
}

// AcceptConsent tells hydra to accept a consent request.
func AcceptConsent(client *http.Client, hydraAdminURL, challenge string, r *hydraapi.HandledConsentRequest) (*hydraapi.RequestHandlerResponse, error) {
	u := putURL(hydraAdminURL, "consent", "accept", url.QueryEscape(challenge))
	resp := &hydraapi.RequestHandlerResponse{}
	err := httpPut(client, u, r, resp)
	return resp, err
}

// RejectConsent tells hydra to rejects a consent request.
func RejectConsent(client *http.Client, hydraAdminURL, challenge string, r *hydraapi.RequestDeniedError) (*hydraapi.RequestHandlerResponse, error) {
	u := putURL(hydraAdminURL, "consent", "reject", url.QueryEscape(challenge))
	resp := &hydraapi.RequestHandlerResponse{}
	err := httpPut(client, u, r, resp)
	return resp, err
}

// ListClients list all OAuth clients in hydra.
func ListClients(client *http.Client, hydraAdminURL string) ([]*hydraapi.Client, error) {
	u := hydraAdminURL + "/clients"
	resp := []*hydraapi.Client{}
	err := httpGet(client, u, &resp)
	return resp, err
}

// CreateClient creates OAuth client in hydra.
func CreateClient(client *http.Client, hydraAdminURL string, oauthClient *hydraapi.Client) (*hydraapi.Client, error) {
	u := hydraAdminURL + "/clients"
	resp := &hydraapi.Client{}
	err := httpPost(client, u, oauthClient, resp)
	return resp, err
}

// GetClient gets an OAUth 2.0 client by its ID.
func GetClient(client *http.Client, hydraAdminURL, id string) (*hydraapi.Client, error) {
	u := hydraAdminURL + "/clients/" + id
	resp := &hydraapi.Client{}
	err := httpGet(client, u, resp)
	return resp, err
}

// UpdateClient updates an existing OAuth 2.0 Client.
func UpdateClient(client *http.Client, hydraAdminURL, id string, oauthClient *hydraapi.Client) (*hydraapi.Client, error) {
	u := hydraAdminURL + "/clients/" + id
	resp := &hydraapi.Client{}
	err := httpPut(client, u, oauthClient, resp)
	return resp, err
}

// DeleteClient delete an existing OAuth 2.0 Client by its ID.
func DeleteClient(client *http.Client, hydraAdminURL, id string) error {
	u := hydraAdminURL + "/clients/" + id
	err := httpDelete(client, u)
	return err
}

// Introspect token, validate the given token and return token claims.
func Introspect(client *http.Client, hydraAdminURL, token string) (*hydraapi.Introspection, error) {
	u := hydraAdminURL + "/oauth2/introspect"

	data := url.Values{}
	data.Set("token", url.QueryEscape(token))

	response := &hydraapi.Introspection{}

	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if err := httpResponse(resp, response); err != nil {
		return nil, err
	}
	return response, nil
}

func getURL(hydraAdminURL, flow, challenge string) string {
	const getURLPattern = "%s/oauth2/auth/requests/%s?%s_challenge=%s"
	return fmt.Sprintf(getURLPattern, hydraAdminURL, flow, flow, url.QueryEscape(challenge))
}

func putURL(hydraAdminURL, flow, action, challenge string) string {
	const putURLPattern = "%s/oauth2/auth/requests/%s/%s?%s_challenge=%s"
	return fmt.Sprintf(putURLPattern, hydraAdminURL, flow, action, flow, url.QueryEscape(challenge))
}

func httpResponse(resp *http.Response, response interface{}) error {
	if httputil.IsHTTPError(resp.StatusCode) {
		gErr := &hydraapi.GenericError{}
		if err := common.DecodeJSONFromBody(resp.Body, gErr); err != nil {
			return err
		}
		// TODO: figure out what error from hydra should handle.
		return gErr
	}

	return common.DecodeJSONFromBody(resp.Body, response)
}

func httpPut(client *http.Client, url string, request interface{}, response interface{}) error {
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	return httpResponse(resp, response)
}

func httpPost(client *http.Client, url string, request interface{}, response interface{}) error {
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	return httpResponse(resp, response)
}

func httpDelete(client *http.Client, url string) error {
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return httpResponse(resp, nil)
}

func httpGet(client *http.Client, url string, response interface{}) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	return httpResponse(resp, response)
}
