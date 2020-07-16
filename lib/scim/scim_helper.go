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

package scim

import (
	"context"
	"strings"
	"time"

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/pborman/uuid" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/kms" /* copybara-comment: kms */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
)

// UpdateIdentityInAccount updates the identity in a existing account.
func UpdateIdentityInAccount(ctx context.Context, id *ga4gh.Identity, provider string, acct *pb.Account, encryption kms.Encryption) (*pb.Account, error) {
	index, ca := findConnectedAccount(id, provider, acct)
	if ca == nil {
		// internal error because acct found by account lookup by id.
		return nil, status.Error(codes.Internal, "can not find ConnectedAccount in account")
	}

	newCa, err := toConnectedAccount(ctx, encryption, id, provider)
	if err != nil {
		return nil, err
	}

	newCa.Revision = ca.Revision + 1
	acct.ConnectedAccounts[index] = newCa

	// TODO: update account properties and account profile

	return acct, nil
}

// NewAccount for given identity.
func NewAccount(ctx context.Context, encryption kms.Encryption, id *ga4gh.Identity, provider, accountNamePrefix string, genAccountNameLen int) (*pb.Account, *pb.AccountLookup, error) {
	n := accountNamePrefix + strings.Replace(uuid.New(), "-", "", -1)
	n = n[:genAccountNameLen]

	now := time.Now()

	ca, err := toConnectedAccount(ctx, encryption, id, provider)
	if err != nil {
		return nil, nil, err
	}

	acct := &pb.Account{
		Revision:          0,
		Profile:           setupAccountProfile(id),
		Properties:        setupAccountProperties(id, n, now, now),
		ConnectedAccounts: []*pb.ConnectedAccount{ca},
		State:             storage.StateActive,
		Ui:                map[string]string{},
	}

	lookup := &pb.AccountLookup{
		Subject:  acct.Properties.Subject,
		Revision: 0,
		State:    storage.StateActive,
	}

	return acct, lookup, nil
}

func findConnectedAccount(id *ga4gh.Identity, provider string, acct *pb.Account) (int, *pb.ConnectedAccount) {
	for i, ca := range acct.ConnectedAccounts {
		if ca.Provider == provider && ca.Properties.Subject == id.Subject {
			return i, ca
		}
	}

	return -1, nil
}

// toConnectedAccount converts identity ConnectedAccount.
func toConnectedAccount(ctx context.Context, encryption kms.Encryption, id *ga4gh.Identity, provider string) (*pb.ConnectedAccount, error) {
	now := time.Now()

	var visas [][]byte
	for _, tok := range id.VisaJWTs {
		encrypted, err := encryption.Encrypt(ctx, []byte(tok), "")
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "encrypt visa failed: %v", err)
		}
		visas = append(visas, encrypted)
	}

	return &pb.ConnectedAccount{
		Passport:     &pb.Passport{InternalEncryptedVisas: visas},
		Profile:      setupAccountProfile(id),
		Properties:   setupAccountProperties(id, id.Subject, now, now),
		Provider:     provider,
		Refreshed:    float64(now.UnixNano()) / 1e9,
		Revision:     1,
		LinkRevision: 1,
	}, nil
}

func setupAccountProfile(id *ga4gh.Identity) *pb.AccountProfile {
	return &pb.AccountProfile{
		Username:   id.Username,
		Name:       id.Name,
		GivenName:  id.GivenName,
		FamilyName: id.FamilyName,
		MiddleName: id.MiddleName,
		Profile:    id.Profile,
		Picture:    id.Picture,
		ZoneInfo:   id.ZoneInfo,
		Locale:     id.Locale,
		Language:   id.Locale, // OIDC Identity does not have "language"
	}
}

func setupAccountProperties(id *ga4gh.Identity, subject string, created, modified time.Time) *pb.AccountProperties {
	return &pb.AccountProperties{
		Subject:       subject,
		Email:         id.Email,
		EmailVerified: id.EmailVerified,
		Created:       float64(created.UnixNano()) / 1e9,
		Modified:      float64(modified.UnixNano()) / 1e9,
	}
}
