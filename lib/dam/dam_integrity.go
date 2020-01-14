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
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/adapter" /* copybara-comment: adapter */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common" /* copybara-comment: common */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/oathclients" /* copybara-comment: oathclients */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/persona" /* copybara-comment: persona */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/validator" /* copybara-comment: validator */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
)

const (
	cfgClaimDefinitions      = "claimDefinitions"
	cfgClients               = "clients"
	cfgOptions               = "options"
	cfgPolicies              = "policies"
	cfgResources             = "resources"
	cfgRoot                  = "cfg"
	cfgServiceTemplates      = "serviceTemplates"
	cfgTestPersonas          = "testPersonas"
	cfgTrustedPassportIssuer = "trustedPassportIssuer"
	cfgTrustedSources        = "trustedSources"
)

var (
	interfaceRE = regexp.MustCompile(`\$\{(.*)\}`)
)

// CheckIntegrity returns an error status if the config is invalid.
func (s *Service) CheckIntegrity(cfg *pb.DamConfig) *status.Status {
	if s.adapters == nil {
		return common.NewStatus(codes.Unavailable, "target adapters not loaded")
	}
	if stat := s.checkBasicIntegrity(cfg); stat != nil {
		return stat
	}
	if stat := s.checkExtraIntegrity(cfg); stat != nil {
		return stat
	}
	return nil
}

func (s *Service) checkBasicIntegrity(cfg *pb.DamConfig) *status.Status {
	for n, ti := range cfg.TrustedPassportIssuers {
		if err := checkName(n); err != nil {
			return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgTrustedPassportIssuer, n), err.Error())
		}
		if !isHTTPS(ti.Issuer) && !isLocalhost(ti.Issuer) {
			return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgTrustedPassportIssuer, n, "issuer"), "trusted identity must have an issuer of type HTTPS")
		}
		if _, ok := translators[ti.TranslateUsing]; !ok && len(ti.TranslateUsing) > 0 {
			return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgTrustedPassportIssuer, n, "translateUsing"), fmt.Sprintf("trusted identity with unknown translator %q", ti.TranslateUsing))
		}
		if path, err := common.CheckUI(ti.Ui, true); err != nil {
			return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgTrustedPassportIssuer, n, path), fmt.Sprintf("trusted passport issuer UI settings: %v", err))
		}
		if stat := checkTrustedIssuerClientCredentials(n, s.defaultBroker, ti); stat != nil {
			return stat
		}
	}

	for n, ts := range cfg.TrustedSources {
		if err := checkName(n); err != nil {
			return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgTrustedSources, n), err.Error())
		}
		for i, source := range ts.Sources {
			if !isHTTPS(source) {
				return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgTrustedSources, n, "sources", strconv.Itoa(i)), "trusted source URL must be HTTPS")
			}
		}
		for i, claim := range ts.Claims {
			if !strings.HasPrefix(claim, "^") {
				// Not a regexp, so just look up the claim name.
				if _, ok := cfg.ClaimDefinitions[claim]; !ok {
					return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgTrustedSources, n, "claims", strconv.Itoa(i)), fmt.Sprintf("claim name %q not found in claim definitions", claim))
				}
				continue
			}
			if !strings.HasSuffix(claim, "$") {
				return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgTrustedSources, n, "claims", strconv.Itoa(i)), fmt.Sprintf("claim regular expression %q does not end with %q", claim, "$"))
			}
			re, err := regexp.Compile(claim)
			if err != nil {
				return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgTrustedSources, n, "claims", strconv.Itoa(i)), fmt.Sprintf("claim regular expression error: %v", err))
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
				return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgTrustedSources, n, "claims", strconv.Itoa(i)), fmt.Sprintf("claim regular expression %q does not match any claim definitions", claim))
			}
		}
		if path, err := common.CheckUI(ts.Ui, true); err != nil {
			return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgTrustedSources, n, path), fmt.Sprintf("trusted sources UI settings: %v", err))
		}
	}

	for n, policy := range cfg.Policies {
		if err := checkName(n); err != nil {
			return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgPolicies, n), err.Error())
		}
		if path, err := validator.ValidatePolicy(policy, cfg.ClaimDefinitions, cfg.TrustedSources, nil); err != nil {
			return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgPolicies, n, path), err.Error())
		}
		if path, err := common.CheckUI(policy.Ui, true); err != nil {
			return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgPolicies, n, path), fmt.Sprintf("policies UI settings: %v", err))
		}
	}

	for n, st := range cfg.ServiceTemplates {
		if stat := s.checkServiceTemplate(n, st, cfg); stat != nil {
			return stat
		}
	}

	for n, res := range cfg.Resources {
		if err := checkName(n); err != nil {
			return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgResources, n), err.Error())
		}
		for i, item := range res.Clients {
			if _, ok := cfg.Clients[item]; !ok {
				return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgResources, n, "clients", strconv.Itoa(i)), fmt.Sprintf("client %q does not exist", item))
			}
		}
		if len(res.MaxTokenTtl) > 0 && !ttlRE.Match([]byte(res.MaxTokenTtl)) {
			return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgResources, n, "maxTokenTtl"), "max token TTL invalid format")
		}
		for vn, view := range res.Views {
			if stat := s.checkViewIntegrity(vn, view, n, res, cfg); stat != nil {
				return stat
			}
		}
		if path, err := common.CheckUI(res.Ui, true); err != nil {
			return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgResources, n, path), fmt.Sprintf("resource UI settings: %v", err))
		}
	}

	for n, cl := range cfg.Clients {
		if err := oathclients.CheckClientIntegrity(n, cl); err != nil {
			return status.Convert(err)
		}
	}

	for n, def := range cfg.ClaimDefinitions {
		if path, err := common.CheckUI(def.Ui, true); err != nil {
			return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgClaimDefinitions, n, path), fmt.Sprintf("claim definitions UI settings: %v", err))
		}
	}

	personaEmail := make(map[string]string)
	for n, tp := range cfg.TestPersonas {
		if err := checkName(n); err != nil {
			return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgTestPersonas, n), err.Error())
		}
		if tp.Passport == nil {
			return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgTestPersonas, n, "passport"), "persona requires a passport")
		}
		tid, err := persona.ToIdentity(n, tp, defaultPersonaScope, "")
		if err != nil {
			return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgTestPersonas, n), fmt.Sprintf("persona to identity: %v", err))
		}
		if len(tid.Issuer) == 0 {
			return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgTestPersonas, n, "passport", "standardClaims", "iss"), "persona requires an issuer")
		}
		if len(tid.Subject) == 0 {
			return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgTestPersonas, n, "passport", "standardClaims", "sub"), "persona requires a subject")
		}
		if pmatch, ok := personaEmail[tid.Subject]; ok {
			return common.NewInfoStatus(codes.AlreadyExists, common.StatusPath(cfgTestPersonas, n, "passport", "standardClaims", "sub"), fmt.Sprintf("persona subject %q conflicts with test persona %q", tid.Subject, pmatch))
		}
		for i, a := range tp.Passport.Ga4GhAssertions {
			// Test Persona conditions should meet the same criteria as policies that have no variables / arguments.
			policy := &pb.Policy{
				AnyOf: a.AnyOfConditions,
			}
			if path, err := validator.ValidatePolicy(policy, cfg.ClaimDefinitions, cfg.TrustedSources, nil); err != nil {
				path = strings.Replace(path, "anyOf/", "anyOfConditions/", 1)
				return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgTestPersonas, n, "passport", "ga4ghAssertions", strconv.Itoa(i), path), err.Error())
			}
		}
		if path, err := common.CheckUI(tp.Ui, false); err != nil {
			return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgTestPersonas, n, path), fmt.Sprintf("test persona UI settings: %v", err))
		}
		// Checking persona expectations is in checkExtraIntegrity() to give an
		// opportunity for runTests() to catch problems and calculate a ConfigModification
		// response.
	}

	if stat := s.checkOptionsIntegrity(cfg.Options); stat != nil {
		return stat
	}

	if path, err := common.CheckUI(cfg.Ui, true); err != nil {
		return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgRoot, path), fmt.Sprintf("root config UI settings: %v", err))
	}

	return nil
}

func (s *Service) checkExtraIntegrity(cfg *pb.DamConfig) *status.Status {
	for n, tp := range cfg.TestPersonas {
		for i, access := range tp.Access {
			aparts := strings.Split(access, "/")
			if len(aparts) != 3 {
				return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgTestPersonas, n, "access", strconv.Itoa(i)), "invalid access entry format (expecting 'resourceName/viewName/roleName')")
			}
			rn := aparts[0]
			vn := aparts[1]
			rolename := aparts[2]
			res, ok := cfg.Resources[rn]
			if !ok {
				return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgTestPersonas, n, "access", strconv.Itoa(i), "resource"), fmt.Sprintf("access entry resource %q not found", rn))
			}
			view, ok := res.Views[vn]
			if !ok {
				return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgTestPersonas, n, "access", strconv.Itoa(i), "view"), fmt.Sprintf("access entry view %q not found", vn))
			}
			roleView := s.makeView(vn, view, res, cfg)
			if roleView.AccessRoles == nil {
				return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgTestPersonas, n, "access", strconv.Itoa(i), "role"), fmt.Sprintf("access entry no roles defined for view %q", vn))
			}
			if _, ok := roleView.AccessRoles[rolename]; !ok {
				return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgTestPersonas, n, "access", strconv.Itoa(i), "role"), fmt.Sprintf("access entry role %q not found on view %q", rolename, vn))
			}
		}
	}
	return nil
}

func (s *Service) checkViewIntegrity(name string, view *pb.View, resName string, res *pb.Resource, cfg *pb.DamConfig) *status.Status {
	if err := checkName(name); err != nil {
		return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgResources, resName, "views", name), err.Error())
	}
	if len(view.ServiceTemplate) == 0 {
		return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgResources, resName, "views", name, "serviceTemplate"), "service template is not defined")
	}
	st, ok := cfg.ServiceTemplates[view.ServiceTemplate]
	if !ok {
		return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgResources, resName, "views", name, "serviceTemplate"), fmt.Sprintf("service template %q not found", view.ServiceTemplate))
	}
	if len(view.Version) == 0 {
		return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgResources, resName, "views", name, "version"), "version is empty")
	}
	if path, err := s.checkAccessRequirements(view.ServiceTemplate, st, resName, name, view, cfg); err != nil {
		return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgResources, resName, path), fmt.Sprintf("access requirements: %v", err))
	}
	if len(view.DefaultRole) == 0 {
		return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgResources, resName, "views", name, "defaultRole"), "default role is empty")
	}
	if _, ok := view.AccessRoles[view.DefaultRole]; !ok {
		return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgResources, resName, "views", name, "defaultRole"), "default role is not defined within the view")
	}
	if len(view.ComputedInterfaces) > 0 {
		return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgResources, resName, "views", name, "interfaces"), "interfaces should be determined at runtime and cannot be stored as part of the config")
	}
	if path, err := common.CheckUI(view.Ui, true); err != nil {
		return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgResources, resName, "views", name, path), fmt.Sprintf("view UI settings: %v", err))
	}

	return nil
}

func (s *Service) checkServiceTemplate(name string, template *pb.ServiceTemplate, cfg *pb.DamConfig) *status.Status {
	if err := checkName(name); err != nil {
		return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgServiceTemplates, name), err.Error())
	}
	if len(template.TargetAdapter) == 0 {
		return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgServiceTemplates, name, "targetAdapter"), "target adapter is not specified")
	}
	adapt, ok := s.adapters.ByName[template.TargetAdapter]
	if !ok {
		return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgServiceTemplates, name, "targetAdapter"), "target adapter is not a recognized adapter within this service")
	}
	if path, err := adapt.CheckConfig(name, template, "", "", nil, cfg, s.adapters); err != nil {
		return common.NewInfoStatus(codes.InvalidArgument, path, err.Error())
	}
	if len(template.ItemFormat) == 0 {
		return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgServiceTemplates, name, "itemFormat"), "item format is not specified")
	}
	if _, ok = adapt.Descriptor().ItemFormats[template.ItemFormat]; !ok {
		return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgServiceTemplates, name, "itemFormat"), fmt.Sprintf("item format %q is invalid", template.ItemFormat))
	}
	if path, err := s.checkServiceRoles(template.ServiceRoles, name, template.TargetAdapter, template.ItemFormat, cfg); err != nil {
		return common.NewInfoStatus(codes.InvalidArgument, path, err.Error())
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
				return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgServiceTemplates, name, "interfaces", k), fmt.Sprintf("interface %q variable %q not defined for this target adapter", k, varName))
			}
		}
	}
	if path, err := common.CheckUI(template.Ui, true); err != nil {
		return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgServiceTemplates, name, path), fmt.Sprintf("service template UI settings: %v", err))
	}
	return nil
}

func (s *Service) checkAccessRequirements(templateName string, template *pb.ServiceTemplate, resName, viewName string, view *pb.View, cfg *pb.DamConfig) (string, error) {
	adapt, ok := s.adapters.ByName[template.TargetAdapter]
	if !ok {
		return common.StatusPath("targetAdapter"), fmt.Errorf("service template %q adapter %q is not a recognized adapter within this service", templateName, template.TargetAdapter)
	}
	if path, err := adapt.CheckConfig(templateName, template, resName, viewName, view, cfg, s.adapters); err != nil {
		return path, err
	}
	if path, err := s.checkAccessRoles(view.AccessRoles, templateName, template.TargetAdapter, template.ItemFormat, cfg); err != nil {
		return common.StatusPath("views", viewName, "roles", path), fmt.Errorf("view %q roles: %v", viewName, err)
	}
	desc := adapt.Descriptor()
	if desc.Requirements.Aud && len(view.Aud) == 0 {
		return common.StatusPath("views", viewName, "aud"), fmt.Errorf("view %q does not provide an audience", viewName)
	}
	if len(desc.ItemFormats) > 0 && len(view.Items) == 0 {
		return common.StatusPath("views", viewName, "items"), fmt.Errorf("view %q does not provide any target items", viewName)
	}
	if len(desc.ItemFormats) > 0 && desc.Properties != nil && desc.Properties.SingleItem && len(view.Items) > 1 {
		return common.StatusPath("views", viewName, "items"), fmt.Errorf("view %q provides more than one item when only one was expected for adapter %q", viewName, template.TargetAdapter)
	}
	for idx, item := range view.Items {
		vars, path, err := adapter.GetItemVariables(s.adapters, template.TargetAdapter, template.ItemFormat, item)
		if err != nil {
			return common.StatusPath("views", viewName, "items", strconv.Itoa(idx), path), err
		}
		if len(vars) == 0 {
			return common.StatusPath("views", viewName, "items", strconv.Itoa(idx), "vars"), fmt.Errorf("no variables defined")
		}
	}
	return "", nil
}

func (s *Service) checkAccessRoles(roles map[string]*pb.AccessRole, templateName, targetAdapter, itemFormat string, cfg *pb.DamConfig) (string, error) {
	if len(roles) == 0 {
		return "", fmt.Errorf("does not provide any roles")
	}
	desc := s.adapters.Descriptors[targetAdapter]
	for rname, role := range roles {
		if err := checkName(rname); err != nil {
			return common.StatusPath(rname), fmt.Errorf("role has invalid name %q: %v", rname, err)
		}
		if len(role.ComputedPolicyBasis) > 0 {
			return common.StatusPath(rname, "policyBasis"), fmt.Errorf("role %q interfaces should be determined at runtime and cannot be stored as part of the config", rname)
		}
		if role.Policies != nil {
			for i, p := range role.Policies {
				if len(p.Name) == 0 {
					return common.StatusPath(rname, "policies", strconv.Itoa(i), "name"), fmt.Errorf("access policy name is not defined")
				}
				policy, ok := cfg.Policies[p.Name]
				if !ok {
					return common.StatusPath(rname, "policies", strconv.Itoa(i), "name"), fmt.Errorf("policy %q is not defined", p.Name)
				}
				if path, err := validator.ValidatePolicy(policy, cfg.ClaimDefinitions, cfg.TrustedSources, p.Vars); err != nil {
					return common.StatusPath(rname, "policies", strconv.Itoa(i), path), err
				}
			}
		}
		if len(role.Policies) == 0 && !desc.Properties.IsAggregate {
			return common.StatusPath(rname, "policies"), fmt.Errorf("must provice at least one target policy")
		}
	}
	return "", nil
}

func (s *Service) checkServiceRoles(roles map[string]*pb.ServiceRole, templateName, targetAdapter, itemFormat string, cfg *pb.DamConfig) (string, error) {
	if len(roles) == 0 {
		return common.StatusPath(cfgServiceTemplates, templateName, "roles"), fmt.Errorf("no roles provided")
	}
	desc := s.adapters.Descriptors[targetAdapter]
	for rname, role := range roles {
		if err := checkName(rname); err != nil {
			return common.StatusPath(cfgServiceTemplates, templateName, "roles", rname), fmt.Errorf("role has invalid name %q: %v", rname, err)
		}
		if len(role.DamRoleCategories) == 0 {
			return common.StatusPath(cfgServiceTemplates, templateName, "roles", rname, "damRoleCategories"), fmt.Errorf("role %q does not provide a DAM role category", rname)
		}
		for i, pt := range role.DamRoleCategories {
			if _, ok := s.roleCategories[pt]; !ok {
				return common.StatusPath(cfgServiceTemplates, templateName, "roles", rname, "damRoleCategories", strconv.Itoa(i)), fmt.Errorf("role %q DAM role category %q is not defined (valid types are: %s)", rname, pt, strings.Join(roleCategorySet(s.roleCategories), ", "))
			}
		}
		if desc.Requirements.TargetRole && len(role.TargetRoles) == 0 {
			return common.StatusPath(cfgServiceTemplates, templateName, "roles", rname, "targetRoles"), fmt.Errorf("role %q does not provide any target role assignments", rname)
		}
		for ri, rv := range role.TargetRoles {
			if len(rv) == 0 {
				return common.StatusPath(cfgServiceTemplates, templateName, "roles", rname, "targetRoles", strconv.Itoa(ri)), fmt.Errorf("target role is empty")
			}
		}
		if desc.Requirements.TargetScope && len(role.TargetScopes) == 0 {
			return common.StatusPath(cfgServiceTemplates, templateName, "roles", rname, "targetScopes"), fmt.Errorf("role %q does not provide any target scopes assignments", rname)
		}
		if path, err := common.CheckUI(role.Ui, true); err != nil {
			return common.StatusPath(cfgServiceTemplates, templateName, "roles", rname, path), fmt.Errorf("role %q: %v", rname, err)
		}
	}
	return "", nil
}

func (s *Service) checkOptionsIntegrity(opts *pb.ConfigOptions) *status.Status {
	if opts == nil {
		return nil
	}
	// Get the descriptors.
	opts = makeConfigOptions(opts)
	if err := common.CheckStringListOption(opts.WhitelistedRealms, "whitelistedRealms", opts.ComputedDescriptors); err != nil {
		return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgOptions, "whitelistedRealms"), err.Error())
	}
	if err := common.CheckStringOption(opts.GcpManagedKeysMaxRequestedTtl, "gcpManagedKeysMaxRequestedTtl", opts.ComputedDescriptors); err != nil {
		return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgOptions, "gcpManagedKeysMaxRequestedTtl"), err.Error())
	}
	if err := common.CheckIntOption(opts.GcpManagedKeysPerAccount, "gcpManagedKeysPerAccount", opts.ComputedDescriptors); err != nil {
		return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgOptions, "gcpManagedKeysPerAccount"), err.Error())
	}
	if err := common.CheckStringOption(opts.GcpServiceAccountProject, "gcpServiceAccountProject", opts.ComputedDescriptors); err != nil {
		return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgOptions, "gcpServiceAccountProject"), err.Error())
	}
	return nil
}

func (s *Service) configCheckIntegrity(cfg *pb.DamConfig, mod *pb.ConfigModification, r *http.Request) *status.Status {
	bad := codes.InvalidArgument
	if err := common.CheckReadOnly(getRealm(r), cfg.Options.ReadOnlyMasterRealm, cfg.Options.WhitelistedRealms); err != nil {
		return common.NewStatus(bad, err.Error())
	}
	if len(cfg.Version) == 0 {
		return common.NewStatus(bad, "missing config version")
	}
	if cfg.Revision <= 0 {
		return common.NewStatus(bad, "invalid config revision")
	}
	if err := configRevision(mod, cfg); err != nil {
		return common.NewStatus(bad, err.Error())
	}
	if stat := s.updateTests(cfg, mod); stat != nil {
		return stat
	}
	if stat := s.checkBasicIntegrity(cfg); stat != nil {
		return stat
	}
	if tests := s.runTests(cfg, nil); hasTestError(tests) {
		stat := common.NewStatus(codes.FailedPrecondition, tests.Error)
		return common.AddStatusDetails(stat, tests.Modification)
	}
	if stat := s.checkExtraIntegrity(cfg); stat != nil {
		return stat
	}
	return nil
}

func checkTrustedIssuerClientCredentials(name, defaultBroker string, tpi *pb.TrustedPassportIssuer) *status.Status {
	if name != defaultBroker {
		return nil
	}
	if len(tpi.AuthUrl) == 0 {
		return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgTrustedPassportIssuer, name, "authUrl"), "AuthUrl not provided")
	}
	if len(tpi.TokenUrl) == 0 {
		return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgTrustedPassportIssuer, name, "tokenUrl"), "TokenUrl not provided")
	}
	return nil
}

func (s *Service) checkTrustedIssuer(iss string, cfg *pb.DamConfig) *status.Status {
	if len(iss) == 0 {
		return common.NewStatus(codes.PermissionDenied, "unauthorized missing passport issuer")
	}
	foundIssuer := false
	for _, tpi := range cfg.TrustedPassportIssuers {
		if iss == tpi.Issuer {
			foundIssuer = true
			break
		}
	}
	if !foundIssuer {
		return common.NewStatus(codes.PermissionDenied, fmt.Sprintf("unauthorized passport issuer %q", iss))
	}
	return nil
}

func rmTestResource(cfg *pb.DamConfig, name string) {
	prefix := name + "/"
	for _, p := range cfg.TestPersonas {
		p.Access = common.FilterStringsByPrefix(p.Access, prefix)
	}
}

func rmTestView(cfg *pb.DamConfig, resName, viewName string) {
	prefix := resName + "/" + viewName + "/"
	for _, p := range cfg.TestPersonas {
		p.Access = common.FilterStringsByPrefix(p.Access, prefix)
	}
}

func (s *Service) updateTests(cfg *pb.DamConfig, modification *pb.ConfigModification) *status.Status {
	if modification == nil {
		return nil
	}
	for name, td := range modification.TestPersonas {
		p, ok := cfg.TestPersonas[name]
		if !ok {
			return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgTestPersonas, name), fmt.Sprintf("test persona %q not found", name))
		}
		p.Access = td.Access
		sort.Strings(p.Access)
	}
	return nil
}

func (s *Service) runTests(cfg *pb.DamConfig, resources []string) *pb.GetTestResultsResponse {
	t := float64(time.Now().UnixNano()) / 1e9
	personas := make(map[string]*cpb.TestPersona)
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
	for pname, p := range cfg.TestPersonas {
		tc++
		personas[pname] = &cpb.TestPersona{
			Passport: p.Passport,
			Access:   p.Access,
		}
		status, got, err := s.testPersona(pname, resources, cfg)
		e := ""
		if err == nil {
			passed++
		} else {
			e = err.Error()
		}
		results = append(results, &pb.GetTestResultsResponse_TestResult{
			Name:   pname,
			Result: status,
			Access: got,
			Error:  e,
		})
		s.calculateModification(pname, p.Access, got, modification)
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

func (s *Service) calculateModification(name string, want []string, got []string, modification *pb.ConfigModification) {
	entry, ok := modification.TestPersonas[name]
	if !ok {
		entry = &pb.ConfigModification_PersonaModification{
			Access:       got,
			AddAccess:    []string{},
			RemoveAccess: []string{},
		}
		modification.TestPersonas[name] = entry
	}
	s.deltaResourceModification(entry, want, got)
	if len(entry.AddAccess) == 0 && len(entry.RemoveAccess) == 0 {
		delete(modification.TestPersonas, name)
	}
}

func (s *Service) deltaResourceModification(entry *pb.ConfigModification_PersonaModification, want []string, got []string) bool {
	// Assumes view list entries are sorted on both |want| and |got|.
	var add []string
	var rm []string
	w := 0
	g := 0
	wl := 0
	if want != nil {
		wl = len(want)
	}
	gl := 0
	if got != nil {
		gl = len(got)
	}
	for w < wl || g < gl {
		if w >= wl {
			add = append(add, got[g:]...)
			break
		}
		if g >= gl {
			rm = append(rm, want[w:]...)
			break
		}
		if c := strings.Compare(want[w], got[g]); c == 0 {
			w++
			g++
		} else if c < 0 {
			rm = append(rm, want[w])
			w++
		} else {
			add = append(add, got[g])
			g++
		}
	}
	if len(add) == 0 && len(rm) == 0 {
		return false
	}
	if len(add) > 0 {
		entry.AddAccess = append(entry.AddAccess, add...)
	}
	if len(rm) > 0 {
		entry.RemoveAccess = append(entry.RemoveAccess, rm...)
	}
	return true
}
