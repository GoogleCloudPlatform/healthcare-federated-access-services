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

package check

import (
	"fmt"
	"regexp"
	"strconv"
	"time"

	"google3/net/proto2/go/proto"
	"bitbucket.org/creachadair/stringset" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/timeutil" /* copybara-comment: timeutil */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
)

func CheckReadOnly(realm string, readOnlyMaster bool, whitelistedRealms []string) error {
	if realm == storage.DefaultRealm {
		if readOnlyMaster {
			return fmt.Errorf(`config option "readOnlyMasterRealm" setting prevents updating the config on realm %q`, realm)
		}
	} else if len(whitelistedRealms) > 0 && !stringset.Contains(whitelistedRealms, realm) {
		return fmt.Errorf(`config option "whitelistedRealms" setting prevents updating realm %q config`, realm)
	}
	return nil
}

func CheckStringOption(opt, optName string, descriptors map[string]*cpb.Descriptor) error {
	desc, ok := descriptors[optName]
	if !ok {
		return fmt.Errorf("internal error: option descriptor %q not defined", optName)
	}
	if len(opt) == 0 {
		return nil
	}
	if len(desc.Regexp) > 0 {
		re, err := regexp.Compile(desc.Regexp)
		if err != nil {
			return fmt.Errorf("internal error: option descriptor %q regexp %q does not compile", optName, desc.Regexp)
		}
		if !re.Match([]byte(opt)) {
			return fmt.Errorf("option %q: value %q does not match regular expression %q", optName, opt, desc.Regexp)
		}
	}
	if len(desc.EnumValues) > 0 {
		found := false
		for _, v := range desc.EnumValues {
			if v == opt {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("option %q: value %q is not a valid, must be one of: %v", optName, opt, desc.EnumValues)
		}
	}
	if len(desc.Min) > 0 || len(desc.Max) > 0 {
		if desc.Type == "string:duration" {
			val, min, max, err := OptDuration(optName, opt, desc.Min, desc.Max)
			if err != nil {
				return err
			}
			if (min != 0 && val < min) || (max != 0 && val > max) {
				return fmt.Errorf("option %q: value %q is not within range (duration range is %s to %s)", optName, opt, desc.Min, desc.Max)
			}
		} else {
			min := int(OptInt(desc.Min))
			max := int(OptInt(desc.Max))
			if (min != 0 && len(opt) < min) || (max != 0 && len(opt) > max) {
				return fmt.Errorf("option %q: value %q is too short or too long (range is %s to %s)", optName, opt, desc.Min, desc.Max)
			}
		}
	}
	return nil
}

func CheckStringListOption(values []string, optName string, descriptors map[string]*cpb.Descriptor) error {
	for _, v := range values {
		if err := CheckStringOption(v, optName, descriptors); err != nil {
			return err
		}
	}
	return nil
}

func CheckIntOption(opt int32, optName string, descriptors map[string]*cpb.Descriptor) error {
	desc, ok := descriptors[optName]
	if !ok {
		return fmt.Errorf("internal error: option descriptor %q not defined", optName)
	}
	if opt == 0 {
		// Is default value and does not need to meet min/max requirements.
		return nil
	}
	min := OptInt(desc.Min)
	max := OptInt(desc.Max)
	if (min != 0 && opt < min) || (max != 0 && opt > max) {
		return fmt.Errorf("option %q: value %d is out of range (%s to %s)", optName, opt, desc.Min, desc.Max)
	}
	return nil
}

func OptInt(str string) int32 {
	if len(str) == 0 {
		return 0
	}
	out, err := strconv.ParseInt(str, 10, 32)
	if err != nil {
		return 0
	}
	return int32(out)
}

func OptDuration(optName, optVal, minVal, maxVal string) (time.Duration, time.Duration, time.Duration, error) {
	v, err := timeutil.ParseDuration(optVal)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("option %q: value %q format error: %v", optName, optVal, err)
	}
	min, err := timeutil.ParseDuration(minVal)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("option %q: minimum %q format error: %v", optName, minVal, err)
	}
	max, err := timeutil.ParseDuration(maxVal)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("option %q: maximum %q format error: %v", optName, maxVal, err)
	}
	return v, min, max, nil
}

// CheckUI checks UI object in config.
func CheckUI(ui map[string]string, requireDescription bool) (string, error) {
	if ui == nil {
		return "ui", fmt.Errorf("UI object missing")
	}

	if label := ui["label"]; len(label) == 0 {
		return httputils.StatusPath("ui", "label"), fmt.Errorf("UI object missing %q field", "label")
	}

	if !requireDescription {
		return "", nil
	}

	if desc := ui["description"]; len(desc) == 0 {
		return httputils.StatusPath("ui", "description"), fmt.Errorf("UI object missing %q field", "description")
	}

	return "", nil
}

// ClientsEqual compares two maps of Client protos and returns true if equal.
func ClientsEqual(a, b map[string]*cpb.Client) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		vb, ok := b[k]
		if !ok {
			return false
		}
		if !proto.Equal(va, vb) {
			return false
		}
	}
	return true
}
