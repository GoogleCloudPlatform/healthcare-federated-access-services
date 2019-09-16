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

package dam

import (
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/adapter"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/playground"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/validator"

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1"
)

var (
	interfaceRE = regexp.MustCompile(`\$\{(.*)\}`)
)

func (s *Service) CheckIntegrity(cfg *pb.DamConfig) error {
	if s.adapters == nil {
		return fmt.Errorf("target adapters not loaded")
	}
	if err := s.checkBasicIntegrity(cfg); err != nil {
		return err
	}
	if err := s.checkExtraIntegrity(cfg); err != nil {
		return err
	}
	return nil
}

func (s *Service) checkBasicIntegrity(cfg *pb.DamConfig) error {
	for n, ti := range cfg.TrustedPassportIssuers {
		if err := checkName(n); err != nil {
			return fmt.Errorf("trusted passport issuer name %q: %v", n, err)
		}
		if !isHTTPS(ti.Issuer) && !isLocalhost(ti.Issuer) {
			return fmt.Errorf("trusted identity %q must have an issuer of type HTTPS", n)
		}
		if _, ok := translators[ti.TranslateUsing]; !ok && len(ti.TranslateUsing) > 0 {
			return fmt.Errorf("trusted identity %q as unknown translator %q", n, ti.TranslateUsing)
		}
		if err := common.CheckUI(ti.Ui, true); err != nil {
			return fmt.Errorf("trusted passport issuer %q: %v", n, err)
		}
		if err := checkTrustedIssuerClientCredentials(n, s.defaultBroker, ti); err != nil {
			return fmt.Errorf("trusted passport issuer %q: %v", n, err)
		}
	}

	for n, tc := range cfg.TrustedSources {
		if err := checkName(n); err != nil {
			return fmt.Errorf("trusted claim name %q: %v", n, err)
		}
		for _, source := range tc.Sources {
			if !isHTTPS(source) {
				return fmt.Errorf("trusted claim %q must have an source of type HTTPS", n)
			}
		}
		for _, claim := range tc.Claims {
			if !strings.HasPrefix(claim, "^") {
				// Not a regexp, so just look up the claim name.
				if _, ok := cfg.ClaimDefinitions[claim]; !ok {
					return fmt.Errorf("trusted source %q claim name %q not found in claim definitions", n, claim)
				}
				continue
			}
			if !strings.HasSuffix(claim, "$") {
				return fmt.Errorf("trusted source %q claim regular expression %q does not end with %q", n, claim, "$")
			}
			re, err := regexp.Compile(claim)
			if err != nil {
				return fmt.Errorf("trusted source %q claim regular expression %q: %v", n, claim, err)
			}
			// Regexp should match at least one claim definition.
			match := false
			for defName := range cfg.ClaimDefinitions {
				if re.Match([]byte(defName)) {
					match = true
					break
				}
			}
			if !match {
				return fmt.Errorf("trusted source %q claim regular expression %q does not match any claim definitions", n, claim)
			}
		}
		if err := common.CheckUI(tc.Ui, true); err != nil {
			return fmt.Errorf("trusted claim %q: %v", n, err)
		}
	}

	for n, policy := range cfg.Policies {
		if err := checkName(n); err != nil {
			return fmt.Errorf("policy name %q: %v", n, err)
		}
		if path, err := s.checkConditionIntegrity(n, policy.Allow, "allow", cfg); err != nil {
			return fmt.Errorf("policy name %q condition %q: %v", n, path, err)
		}
		if path, err := s.checkConditionIntegrity(n, policy.Disallow, "disallow", cfg); err != nil {
			return fmt.Errorf("policy name %q condition %q: %v", n, path, err)
		}
		if err := common.CheckUI(policy.Ui, true); err != nil {
			return fmt.Errorf("policy name %q: %v", n, err)
		}
	}
	if _, err := s.resolvePolicies(cfg); err != nil {
		return err
	}

	for n, st := range cfg.ServiceTemplates {
		if err := s.checkServiceTemplate(n, st, cfg); err != nil {
			return err
		}
	}

	for n, res := range cfg.Resources {
		if err := checkName(n); err != nil {
			return fmt.Errorf("resource name %q: %v", n, err)
		}
		for _, item := range res.Clients {
			if _, ok := cfg.Clients[item]; !ok {
				return fmt.Errorf("resource %q client %q does not exist", n, item)
			}
		}
		if len(res.MaxTokenTtl) > 0 && !ttlRE.Match([]byte(res.MaxTokenTtl)) {
			return fmt.Errorf("resource %q max token TTL %q invalid format", n, res.MaxTokenTtl)
		}
		for vn, view := range res.Views {
			if err := s.checkViewIntegrity(vn, view, res, cfg); err != nil {
				return fmt.Errorf("resource %q error: %v", n, err)
			}
		}
		if err := common.CheckUI(res.Ui, true); err != nil {
			return fmt.Errorf("resource name %q: %v", n, err)
		}
	}

	for n, cl := range cfg.Clients {
		if _, err := common.ParseGUID(cl.ClientId); err != nil || len(cl.ClientId) != clientIdLen {
			return fmt.Errorf("client %q does not contain a valid client ID", n)
		}
		if err := common.CheckUI(cl.Ui, true); err != nil {
			return fmt.Errorf("client %q: %v", n, err)
		}
	}

	for n, def := range cfg.ClaimDefinitions {
		if err := common.CheckUI(def.Ui, true); err != nil {
			return fmt.Errorf("claim definition %q: %v", n, err)
		}
	}

	personaEmail := make(map[string]string)
	for n, tp := range cfg.TestPersonas {
		if err := checkName(n); err != nil {
			return fmt.Errorf("test persona name %q: %v", n, err)
		}
		if tp.IdToken == nil {
			return fmt.Errorf("test persona %q requires an ID token", n)
		}
		tid, err := playground.PersonaToIdentity(n, tp, defaultPersonaScope)
		if err != nil {
			return err
		}
		if len(tid.Issuer) == 0 {
			return fmt.Errorf("test persona %q ID token requires an issuer", n)
		}
		if len(tid.Subject) == 0 {
			return fmt.Errorf("test persona %q ID token requires a subject", n)
		}
		if pmatch, ok := personaEmail[tid.Subject]; ok {
			return fmt.Errorf("test persona %q subject %q conflicts with the identity of test persona %q", n, tid.Subject, pmatch)
		}
		if err := common.CheckUI(tp.Ui, false); err != nil {
			return fmt.Errorf("test persona %q: %v", n, err)
		}
		// Checking persona expectations is in checkExtraIntegrity() to give an
		// opportunity for runTests() to catch problems and calculate a ConfigModification
		// response.
	}

	if err := s.checkOptionsIntegrity(cfg.Options); err != nil {
		return err
	}

	if err := common.CheckUI(cfg.Ui, true); err != nil {
		return fmt.Errorf("root config object: %v", err)
	}

	return nil
}

func (s *Service) checkExtraIntegrity(cfg *pb.DamConfig) error {
	for n, tp := range cfg.TestPersonas {
		for tr, alist := range tp.Resources {
			res, ok := cfg.Resources[tr]
			if !ok {
				return fmt.Errorf("test persona %q resource %q not found", n, tr)
			}
			for _, a := range alist.Access {
				aparts := strings.Split(a, "/")
				if len(aparts) != 2 {
					return fmt.Errorf("test persona %q resource %q access %q: invalid format (expecting 'viewName/roleName')", n, tr, a)
				}
				vname := aparts[0]
				rname := aparts[1]
				view, ok := res.Views[vname]
				if !ok {
					return fmt.Errorf("test persona %q resource %q access %q: view %q not found", n, tr, a, vname)
				}
				roleView := s.makeView(vname, view, res, cfg)
				if roleView.AccessRoles == nil {
					return fmt.Errorf("test persona %q resource %q access %q: no roles defined", n, tr, a)
				}
				if _, ok := roleView.AccessRoles[rname]; !ok {
					return fmt.Errorf("test persona %q resource %q access %q: role %q not defined", n, tr, a, rname)
				}
			}
		}
	}
	return nil
}

func (s *Service) checkViewIntegrity(name string, view *pb.View, res *pb.Resource, cfg *pb.DamConfig) error {
	if err := checkName(name); err != nil {
		return fmt.Errorf("view name %q: %v", name, err)
	}
	if len(view.ServiceTemplate) == 0 {
		return fmt.Errorf("view %q service template is not defined", name)
	}
	st, ok := cfg.ServiceTemplates[view.ServiceTemplate]
	if !ok {
		return fmt.Errorf("view %q service template %q not found", name, view.ServiceTemplate)
	}
	if len(view.Version) == 0 {
		return fmt.Errorf("view %q version is not defined", name)
	}
	if err := s.checkAccessRequirements(view.ServiceTemplate, st, name, view, cfg); err != nil {
		return fmt.Errorf("view %q: %v", name, err)
	}
	if len(view.DefaultRole) == 0 {
		return fmt.Errorf("view %q does not provide a default role", name)
	}
	if _, ok := view.AccessRoles[view.DefaultRole]; !ok {
		return fmt.Errorf("view %q default role %q is not defined in any grants within the view", name, view.DefaultRole)
	}
	if len(view.ComputedInterfaces) > 0 {
		return fmt.Errorf("view %q interfaces should be determined at runtime and cannot be stored as part of the config", name)
	}
	if err := common.CheckUI(view.Ui, true); err != nil {
		return fmt.Errorf("view name %q: %v", name, err)
	}

	return nil
}

func (s *Service) checkServiceTemplate(name string, template *pb.ServiceTemplate, cfg *pb.DamConfig) error {
	if err := checkName(name); err != nil {
		return fmt.Errorf("service template name %q: %v", name, err)
	}
	if len(template.TargetAdapter) == 0 {
		return fmt.Errorf("service template %q adapter is not specified", name)
	}
	adapt, ok := s.adapters.ByName[template.TargetAdapter]
	if !ok {
		return fmt.Errorf("service template %q adapter %q is not a recognized adapter within this service", name, template.TargetAdapter)
	}
	if err := adapt.CheckConfig(name, template, "", nil, cfg, s.adapters); err != nil {
		return err
	}
	if len(template.ItemFormat) == 0 {
		return fmt.Errorf("service template %q item format is not specified", name)
	}
	if _, ok = adapt.Descriptor().ItemFormats[template.ItemFormat]; !ok {
		return fmt.Errorf("service template %q item format %q is not valid", name, template.ItemFormat)
	}
	if err := s.checkServiceRoles(template.ServiceRoles, template.TargetAdapter, template.ItemFormat, false, cfg); err != nil {
		return fmt.Errorf("service template %q roles: %v", name, err)
	}
	varNames := make(map[string]bool)
	desc := s.adapters.Descriptors[template.TargetAdapter]
	for _, v := range desc.ItemFormats {
		for varName := range v.Variables {
			varNames[varName] = true
		}
	}
	for k, v := range template.Interfaces {
		match := interfaceRE.FindAllString(v, -1)
		for _, varMatch := range match {
			// Remove the `${` prefix and `}` suffix.
			varName := varMatch[2 : len(varMatch)-1]
			if _, ok := varNames[varName]; !ok {
				return fmt.Errorf("service template %q interface %q variable name %q not defined for adapter %q", name, k, varName, template.TargetAdapter)
			}
		}
	}
	if err := common.CheckUI(template.Ui, true); err != nil {
		return fmt.Errorf("service template %q: %v", name, err)
	}
	return nil
}

func (s *Service) checkAccessRequirements(templateName string, template *pb.ServiceTemplate, viewName string, view *pb.View, cfg *pb.DamConfig) error {
	adapt, ok := s.adapters.ByName[template.TargetAdapter]
	if !ok {
		return fmt.Errorf("service template %q adapter %q is not a recognized adapter within this service", templateName, template.TargetAdapter)
	}
	if err := adapt.CheckConfig(templateName, template, viewName, view, cfg, s.adapters); err != nil {
		return err
	}
	if err := s.checkAccessRoles(view.AccessRoles, template.TargetAdapter, template.ItemFormat, true, cfg); err != nil {
		return fmt.Errorf("view %q roles: %v", viewName, err)
	}
	desc := adapt.Descriptor()
	if desc.Requirements.Aud && len(view.Aud) == 0 {
		return fmt.Errorf("view %q does not provide an audience", viewName)
	}
	if len(desc.ItemFormats) > 0 && len(view.Items) == 0 {
		return fmt.Errorf("view %q does not provide any target items", viewName)
	}
	if len(desc.ItemFormats) > 0 && desc.Properties != nil && desc.Properties.SingleItem && len(view.Items) > 1 {
		return fmt.Errorf("view %q provides more than one item when only one was expected for adapter %q", viewName, template.TargetAdapter)
	}
	for idx, item := range view.Items {
		vars, err := adapter.GetItemVariables(s.adapters, template.TargetAdapter, template.ItemFormat, item)
		if err != nil {
			return fmt.Errorf("item %d: %v", idx, err)
		}
		if len(vars) == 0 {
			return fmt.Errorf("view %q item %d has no variables defined", viewName, idx+1)
		}
	}
	return nil
}

func (s *Service) checkAccessRoles(roles map[string]*pb.AccessRole, targetAdapter, itemFormat string, requirementCheck bool, cfg *pb.DamConfig) error {
	if requirementCheck && len(roles) == 0 {
		return fmt.Errorf("does not provide any roles")
	}
	desc := s.adapters.Descriptors[targetAdapter]
	for rname, role := range roles {
		if err := checkName(rname); err != nil {
			return fmt.Errorf("role has invalid name %q: %v", rname, err)
		}
		if len(role.ComputedPolicyBasis) > 0 {
			return fmt.Errorf("role %q interfaces should be determined at runtime and cannot be stored as part of the config", rname)
		}
		if role.Policies != nil {
			for _, policy := range role.Policies {
				pname := strings.SplitN(policy, "(", 2)[0]
				if _, ok := cfg.Policies[pname]; !ok {
					return fmt.Errorf("role %q target policy %q is not defined", rname, pname)
				}
			}
		}
		if requirementCheck && len(role.Policies) == 0 && !desc.Properties.IsAggregate {
			return fmt.Errorf("role %q is configured but does not provide any target policy", rname)
		}
	}
	return nil
}

func (s *Service) checkServiceRoles(roles map[string]*pb.ServiceRole, targetAdapter, itemFormat string, requirementCheck bool, cfg *pb.DamConfig) error {
	if requirementCheck && len(roles) == 0 {
		return fmt.Errorf("does not provide any roles")
	}
	desc := s.adapters.Descriptors[targetAdapter]
	for rname, role := range roles {
		if err := checkName(rname); err != nil {
			return fmt.Errorf("role has invalid name %q: %v", rname, err)
		}
		if requirementCheck && len(role.DamRoleCategories) == 0 {
			return fmt.Errorf("role %q does not provide a DAM role category", rname)
		}
		for _, pt := range role.DamRoleCategories {
			if _, ok := s.roleCategories[pt]; !ok {
				return fmt.Errorf("role %q DAM role category %q is not defined (valid types are: %s)", rname, pt, strings.Join(roleCategorySet(s.roleCategories), ", "))
			}
		}
		if requirementCheck && desc.Requirements.TargetRole && len(role.TargetRoles) == 0 {
			return fmt.Errorf("role %q does not provide any target role assignments", rname)
		}
		for ri, rv := range role.TargetRoles {
			if len(rv) == 0 {
				return fmt.Errorf("role %q value %d is empty", rname, ri+1)
			}
		}
		if requirementCheck && desc.Requirements.TargetScope && len(role.TargetScopes) == 0 {
			return fmt.Errorf("role %q does not provide any target scopes assignments", rname)
		}
		if err := common.CheckUI(role.Ui, true); err != nil {
			return fmt.Errorf("role %q: %v", rname, err)
		}
	}
	return nil
}

func (s *Service) checkConditionIntegrity(policyName string, cond *pb.Condition, path string, cfg *pb.DamConfig) (string, error) {
	if cond == nil {
		return path, nil
	}
	n := ""
	claim := ""
	if len(cond.AllTrue) > 0 {
		n = "/allTrue"
	}
	if len(cond.AnyTrue) > 0 {
		n = "/anyTrue"
	}
	switch k := cond.Key.(type) {
	case *pb.Condition_Claim:
		n = "/claim:" + k.Claim
		claim = k.Claim
	case *pb.Condition_DataUse:
		n = "/claim:" + k.DataUse
	}
	// Must contain one of: AllTrue, AnyTrue, {Claim, *Value}, {DataUse, StrValue}.
	if err := validator.ValidateCondition(cond, cfg.ClaimDefinitions); err != nil {
		return path, err
	}
	path = path + n
	if len(cond.Is) > 0 && len(claim) == 0 {
		return path, fmt.Errorf(`comparison "is" type is only for use with claim names`)
	}
	for _, f := range cond.From {
		if _, ok := cfg.TrustedSources[f]; !ok {
			return path, fmt.Errorf(`"from" restriction %q does not match any Trusted Source names`, f)
		}
	}
	// TODO: support for userlists.
	for i, sub := range cond.AnyTrue {
		if p, err := s.checkConditionIntegrity(policyName, sub, fmt.Sprintf("%s:%d", path, i), cfg); err != nil {
			return p, err
		}
	}
	for i, sub := range cond.AllTrue {
		if p, err := s.checkConditionIntegrity(policyName, sub, fmt.Sprintf("%s:%d", path, i), cfg); err != nil {
			return p, err
		}
	}
	return path, nil
}

func (s *Service) checkOptionsIntegrity(opts *pb.ConfigOptions) error {
	if opts == nil {
		return nil
	}
	// Get the descriptors.
	opts = makeConfigOptions(opts)
	if err := common.CheckStringListOption(opts.WhitelistedRealms, "whitelistedRealms", opts.ComputedDescriptors); err != nil {
		return err
	}
	if err := common.CheckStringOption(opts.GcpManagedKeysMaxRequestedTtl, "gcpManagedKeysMaxRequestedTtl", opts.ComputedDescriptors); err != nil {
		return err
	}
	if err := common.CheckIntOption(opts.GcpManagedKeysPerAccount, "gcpManagedKeysPerAccount", opts.ComputedDescriptors); err != nil {
		return err
	}
	if err := common.CheckStringOption(opts.GcpServiceAccountProject, "gcpServiceAccountProject", opts.ComputedDescriptors); err != nil {
		return err
	}
	return nil
}

func (s *Service) configCheckIntegrity(cfg *pb.DamConfig, mod *pb.ConfigModification, r *http.Request) (proto.Message, int, error) {
	bad := http.StatusBadRequest
	if err := common.CheckReadOnly(getRealm(r), cfg.Options.ReadOnlyMasterRealm, cfg.Options.WhitelistedRealms); err != nil {
		return nil, bad, err
	}
	if len(cfg.Version) == 0 {
		return nil, bad, fmt.Errorf("missing config version")
	}
	if cfg.Revision <= 0 {
		return nil, bad, fmt.Errorf("invalid config revision")
	}
	if err := configRevision(mod, cfg); err != nil {
		return nil, bad, err
	}
	if err := s.updateTests(cfg, mod); err != nil {
		return nil, http.StatusBadRequest, err
	}
	if err := s.checkBasicIntegrity(cfg); err != nil {
		return nil, http.StatusConflict, err
	}
	if tests := s.runTests(cfg, nil); hasTestError(tests) {
		return tests.Modification, http.StatusFailedDependency, fmt.Errorf(tests.Error)
	}
	if err := s.checkExtraIntegrity(cfg); err != nil {
		return nil, http.StatusConflict, err
	}
	return nil, http.StatusOK, nil
}

func checkTrustedIssuerClientCredentials(name, defaultBroker string, tpi *pb.TrustedPassportIssuer) error {
	if name != defaultBroker {
		return nil
	}
	if len(tpi.AuthUrl) == 0 {
		fmt.Errorf("AuthUrl not found")
	}
	if len(tpi.TokenUrl) == 0 {
		fmt.Errorf("TokenUrl not found")
	}
	return nil
}

func (s *Service) checkTrustedIssuer(iss string, cfg *pb.DamConfig) error {
	if len(iss) == 0 {
		return fmt.Errorf("unauthorized missing passport issuer")
	}
	foundIssuer := false
	for _, tpi := range cfg.TrustedPassportIssuers {
		if iss == tpi.Issuer {
			foundIssuer = true
			break
		}
	}
	if !foundIssuer {
		return fmt.Errorf("unauthorized passport issuer %q", iss)
	}
	return nil
}

func rmTestResource(cfg *pb.DamConfig, name string) {
	for _, p := range cfg.TestPersonas {
		if _, ok := p.Resources[name]; ok {
			delete(p.Resources, name)
		}
	}
}

func rmTestView(cfg *pb.DamConfig, resName, viewName string) {
	for _, p := range cfg.TestPersonas {
		alist, ok := p.Resources[resName]
		if !ok {
			continue
		}
		access := []string{}
		prefix := viewName + "/"
		for _, a := range alist.Access {
			if !strings.HasPrefix(a, prefix) {
				access = append(access, a)
			}
		}
		if len(access) == 0 {
			delete(p.Resources, resName)
		} else {
			alist.Access = access
		}
	}
}

func (s *Service) updateTests(cfg *pb.DamConfig, modification *pb.ConfigModification) error {
	if modification == nil {
		return nil
	}
	for name, td := range modification.TestPersonas {
		p, ok := cfg.TestPersonas[name]
		if !ok {
			return fmt.Errorf("test persona %q not found", name)
		}
		if td.Resources != nil {
			p.Resources = make(map[string]*pb.AccessList)
			for r, ra := range td.Resources {
				if ra == nil || len(ra.Access) == 0 {
					continue
				}
				p.Resources[r] = ra
			}
			continue
		}
		// TODO: remove this when removing AddResource/RemoveResource model.
		m := make(map[string]map[string]bool)
		for r, alist := range p.Resources {
			m[r] = make(map[string]bool)
			for _, a := range alist.Access {
				m[r][a] = true
			}
		}
		for r, ra := range td.AddResources {
			if _, ok := cfg.Resources[r]; !ok {
				return fmt.Errorf("test persona %q: add resource %q not found", name, r)
			}
			if _, ok := m[r]; !ok {
				m[r] = make(map[string]bool)
			}
			for _, a := range ra.Access {
				m[r][a] = true
			}
		}
		for r, ra := range td.RemoveResources {
			if _, ok := cfg.Resources[r]; !ok {
				return fmt.Errorf("test persona %q: remove resource %q not found", name, r)
			}
			if _, ok := m[r]; !ok {
				continue
			}
			for _, a := range ra.Access {
				delete(m[r], a)
			}
		}
		p.Resources = make(map[string]*pb.AccessList)
		for r, ra := range m {
			p.Resources[r] = &pb.AccessList{Access: []string{}}
			for a := range ra {
				p.Resources[r].Access = append(p.Resources[r].Access, a)
			}
			sort.Strings(p.Resources[r].Access)
		}
	}
	return nil
}

func (s *Service) runTests(cfg *pb.DamConfig, resources []string) *pb.GetTestResultsResponse {
	t := float64(time.Now().UnixNano()) / 1e9
	personas := make(map[string]*pb.TestPersona)
	results := make([]*pb.GetTestResultsResponse_TestResult, 0)
	passed := int32(0)
	tc := int32(0)
	if resources == nil {
		resources = make([]string, 0, len(cfg.Resources))
		for k := range cfg.Resources {
			resources = append(resources, k)
		}
	}
	modification := &pb.ConfigModification{
		TestPersonas: make(map[string]*pb.ConfigModification_PersonaModification),
	}
	vm, err := s.buildValidatorMap(cfg)
	if err != nil {
		return &pb.GetTestResultsResponse{
			Version:   cfg.Version,
			Revision:  cfg.Revision,
			Timestamp: t,
			Error:     err.Error(),
		}
	}
	for pname, p := range cfg.TestPersonas {
		tc++
		personas[pname] = &pb.TestPersona{
			IdToken:   p.IdToken,
			Resources: p.Resources,
		}
		status, got, err := s.testPersona(pname, resources, cfg, vm)
		e := ""
		if err == nil {
			passed++
		} else {
			e = err.Error()
		}
		results = append(results, &pb.GetTestResultsResponse_TestResult{
			Name:      pname,
			Result:    status,
			Resources: got,
			Error:     e,
		})
		s.calculateModification(pname, resources, p.Resources, got, modification)
	}

	e := ""
	if passed < tc {
		e = fmt.Errorf("%d of %d tests passed, %d failed", passed, tc, tc-passed).Error()
	}
	return &pb.GetTestResultsResponse{
		Version:      cfg.Version,
		Revision:     cfg.Revision,
		Timestamp:    t,
		Personas:     personas,
		TestResults:  results,
		Executed:     tc,
		Passed:       passed,
		Modification: modification,
		Error:        e,
	}
}

func hasTestError(tr *pb.GetTestResultsResponse) bool {
	return len(tr.Error) > 0
}

func (s *Service) calculateModification(name string, resources []string, want map[string]*pb.AccessList, got map[string]*pb.AccessList, modification *pb.ConfigModification) {
	entry, ok := modification.TestPersonas[name]
	if !ok {
		entry = &pb.ConfigModification_PersonaModification{
			Resources:       make(map[string]*pb.AccessList),
			AddResources:    make(map[string]*pb.AccessList),
			RemoveResources: make(map[string]*pb.AccessList),
		}
		modification.TestPersonas[name] = entry
	}

	for _, r := range resources {
		// TODO: remove deltaResourceModification or move setting Resources inside of it.
		hasDelta := s.deltaResourceModification(entry, r, want[r], got[r])
		if hasDelta {
			g := got[r]
			if g == nil {
				g = &pb.AccessList{}
			}
			entry.Resources[r] = g
		}
	}
	if len(entry.AddResources) == 0 && len(entry.RemoveResources) == 0 {
		delete(modification.TestPersonas, name)
	}
}

func (s *Service) deltaResourceModification(entry *pb.ConfigModification_PersonaModification, resource string, want *pb.AccessList, got *pb.AccessList) bool {
	// Assumes view list entries are sorted on both |want| and |got|.
	var add []string
	var rm []string
	w := 0
	g := 0
	wl := 0
	if want != nil {
		wl = len(want.Access)
	}
	gl := 0
	if got != nil {
		gl = len(got.Access)
	}
	for w < wl || g < gl {
		if w >= wl {
			add = append(add, got.Access[g:]...)
			break
		}
		if g >= gl {
			rm = append(rm, want.Access[w:]...)
			break
		}
		if c := strings.Compare(want.Access[w], got.Access[g]); c == 0 {
			w++
			g++
		} else if c < 0 {
			rm = append(rm, want.Access[w])
			w++
		} else {
			add = append(add, got.Access[g])
			g++
		}
	}
	if len(add) == 0 && len(rm) == 0 {
		return false
	}
	if len(add) > 0 {
		entry.AddResources[resource] = &pb.AccessList{
			Access: add,
		}
	}
	if len(rm) > 0 {
		entry.RemoveResources[resource] = &pb.AccessList{
			Access: rm,
		}
	}
	return true
}
