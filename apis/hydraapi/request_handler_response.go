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

// Code generated by go-swagger; DO NOT EDIT.

package hydraapi

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

// RequestHandlerResponse The response payload sent when accepting or rejecting a login or consent request.
// swagger:model RequestHandlerResponse
type RequestHandlerResponse struct {

	// RedirectURL is the URL which you should redirect the user to once the authentication process is completed.
	RedirectTo string `json:"redirect_to,omitempty"`
}
