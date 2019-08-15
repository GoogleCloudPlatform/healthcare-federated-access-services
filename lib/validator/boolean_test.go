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

package validator

import (
	"context"
	"errors"
	"testing"
)

func TestBoolean(t *testing.T) {
	tests := []struct {
		name string
		in   Validator
		ok   bool
		err  bool
	}{
		{
			name: "true and true",
			in:   And{&Constant{OK: true}, &Constant{OK: true}},
			ok:   true,
		},
		{
			name: "true and false",
			in:   And{&Constant{OK: true}, &Constant{OK: false}},
			ok:   false,
		},
		{
			name: "true or true",
			in:   Or{&Constant{OK: true}, &Constant{OK: true}},
			ok:   true,
		},
		{
			name: "false or true",
			in:   Or{&Constant{OK: false}, &Constant{OK: true}},
			ok:   true,
		},
		{
			name: "false or false",
			in:   Or{&Constant{OK: false}, &Constant{OK: false}},
			ok:   false,
		},
		{
			name: "single-input and, true",
			in:   And{&Constant{OK: true}},
			ok:   true,
		},
		{
			name: "single-input and, false",
			in:   And{&Constant{OK: false}},
			ok:   false,
		},
		{
			name: "true and error",
			in:   And{&Constant{OK: true}, &Constant{Err: errors.New("failure")}},
			err:  true,
		},
		{
			name: "false or error",
			in:   Or{&Constant{OK: false}, &Constant{Err: errors.New("failure")}},
			err:  true,
		},
		{
			name: "true and (false or true)",
			in:   And{&Constant{OK: true}, &Or{&Constant{OK: false}, &Constant{OK: true}}},
			ok:   true,
		},
		{
			name: "true and (false or false)",
			in:   And{&Constant{OK: true}, &Or{&Constant{OK: false}, &Constant{OK: false}}},
			ok:   false,
		},
		{
			name: "(true and true) or false",
			in:   Or{&And{&Constant{OK: true}, &Constant{OK: true}}, &Constant{OK: false}},
			ok:   true,
		},
		{
			name: "(true and false) or false",
			in:   Or{&And{&Constant{OK: true}, &Constant{OK: false}}, &Constant{OK: false}},
			ok:   false,
		},
		{
			name: "(true and false) or true",
			in:   Or{&And{&Constant{OK: true}, &Constant{OK: false}}, &Constant{OK: true}},
			ok:   true,
		},
	}
	ctx := context.Background()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ok, err := test.in.Validate(ctx, nil)
			if ok != test.ok {
				t.Fatalf("Unexpected validation result, got = %v, want = %v", ok, test.ok)
			}
			if (err != nil) != test.err {
				t.Fatalf("Unexpected validation error: %v", err)
			}
		})
	}
}
