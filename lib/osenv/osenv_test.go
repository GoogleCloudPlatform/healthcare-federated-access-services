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

package osenv

import (
	"testing"
)

func TestMustVar_ReturnsValueWhenEnvVarSet(t *testing.T) {
	glogExitfOrg := glogExitf
	defer func() { glogExitf = glogExitfOrg }()
	glogExitf = t.Fatalf

	osGetEnvOrg := osGetEnv
	defer func() { osGetEnv = osGetEnvOrg }()
	osGetEnv = func(key string) string { return "env-var-value" }

	key := "set-env-var"
	got := MustVar(key)

	want := "env-var-value"
	if want != got {
		t.Fatalf("MustVar(%v) = %v, want %v", key, got, want)
	}
}

func TestMustVar_DoesNotExitWhenEnvVarSet(t *testing.T) {
	glogExitfOrg := glogExitf
	defer func() { glogExitf = glogExitfOrg }()
	exited := false
	glogExitf = func(format string, args ...interface{}) { exited = true }

	osGetEnvOrg := osGetEnv
	defer func() { osGetEnv = osGetEnvOrg }()
	osGetEnv = func(key string) string { return "env-var-value" }

	key := "set-env-var"
	MustVar(key)

	if exited {
		t.Fatal("MustVar(%v) exited.", key)
	}
}

func TestMustVar_ExitsWhenEnvVarNotSet(t *testing.T) {
	glogExitfOrg := glogExitf
	defer func() { glogExitf = glogExitfOrg }()
	exited := false
	glogExitf = func(format string, args ...interface{}) { exited = true }

	osGetEnvOrg := osGetEnv
	defer func() { osGetEnv = osGetEnvOrg }()
	osGetEnv = func(key string) string { return "" }

	key := "unset-env-var"
	MustVar(key)

	if !exited {
		t.Fatal("MustVar(%v) did not exit.", key)
	}
}

func TestVarWithDefault_ReturnsValueWhenEnvVarSet(t *testing.T) {
	glogExitfOrg := glogExitf
	defer func() { glogExitf = glogExitfOrg }()
	glogExitf = t.Fatalf

	osGetEnvOrg := osGetEnv
	defer func() { osGetEnv = osGetEnvOrg }()
	osGetEnv = func(key string) string { return "env-var-value" }

	key := "set-env-var"
	got := VarWithDefault(key, "default-value")

	want := "env-var-value"
	if want != got {
		t.Fatalf("MustVar(%v) = %v, want %v", key, got, want)
	}
}

func TestVarWithDefault_ReturnsDefaultValueWhenEnvVarNotSet(t *testing.T) {
	glogExitfOrg := glogExitf
	defer func() { glogExitf = glogExitfOrg }()
	glogExitf = t.Fatalf

	osGetEnvOrg := osGetEnv
	defer func() { osGetEnv = osGetEnvOrg }()
	osGetEnv = func(key string) string { return "" }

	key := "set-env-var"
	got := VarWithDefault(key, "default-value")

	want := "default-value"
	if want != got {
		t.Fatalf("MustVar(%v) = %v, want %v", key, got, want)
	}
}
