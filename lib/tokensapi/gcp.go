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

package tokensapi

import (
	"context"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/timeutil" /* copybara-comment: timeutil */

	tpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/tokens/v1" /* copybara-comment: go_proto */
)

// GCPDeleteToken revokes a token.
func (s *DAMTokens) GCPDeleteToken(ctx context.Context, ids []string) error {
	if err := s.saw.DeleteTokens(ctx, ids[1], ids[2], []string{ids[3]}); err != nil {
		return err
	}
	return nil
}

// GCPListTokens lists the tokens.
func (s *DAMTokens) GCPListTokens(ctx context.Context, ids []string) ([]*tpb.Token, error) {
	vs, err := s.saw.ListTokenMetadata(ctx, ids[1], ids[2])
	if err != nil {
		return nil, err
	}
	var tokens []*tpb.Token
	for _, v := range vs {
		t := &tpb.Token{
			Name:      "projects/" + ids[1] + "/users/" + ids[2] + "/tokens/" + v.GetName(),
			IssuedAt:  timeutil.ParseRFC3339(v.GetIssuedAt()).Unix(),
			ExpiresAt: timeutil.ParseRFC3339(v.GetExpires()).Unix(),
		}
		tokens = append(tokens, t)
	}
	return tokens, nil
}
