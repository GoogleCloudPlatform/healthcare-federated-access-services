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
	"context"
	"fmt"
	"net/http"
	"net/mail"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/adapter" /* copybara-comment: adapter */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/check" /* copybara-comment: check */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/oathclients" /* copybara-comment: oathclients */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/persona" /* copybara-comment: persona */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/scim" /* copybara-comment: scim */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/strutil" /* copybara-comment: strutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/validator" /* copybara-comment: validator */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
)

const (
	cfgVisaTypes             = "VisaTypes"
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
func (s *Service) CheckIntegrity(cfg *pb.DamConfig, realm string, tx storage.Tx) *status.Status {
	return ValidateDAMConfig(cfg, s.ValidateCfgOpts(realm, tx))
}

// ValidateCfgOpts returns the options for checking validity of configuration.
func (s *Service) ValidateCfgOpts(realm string, tx storage.Tx) ValidateCfgOpts {
	return ValidateCfgOpts{
		Services:         s.adapters,
		DefaultBroker:    s.defaultBroker,
		RoleCategories:   s.roleCategories,
		HidePolicyBasis:  s.hidePolicyBasis,
		HideRejectDetail: s.hideRejectDetail,
		Scim:             s.scim,
		Realm:            realm,
		Tx:               tx,
	}
}

// ValidateCfgOpts contains options for ValidateDAMConfig.
type ValidateCfgOpts struct {
	Services         *adapter.ServiceAdapters
	DefaultBroker    string
	RoleCategories   map[string]*pb.RoleCategory
	HidePolicyBasis  bool
	HideRejectDetail bool
	Scim             *scim.Scim
	Realm            string
	Tx               storage.Tx
}

// ValidateDAMConfig checks that the provided config is valid.
func ValidateDAMConfig(cfg *pb.DamConfig, vopts ValidateCfgOpts) *status.Status {
	if vopts.Services == nil {
		return httputils.NewStatus(codes.Unavailable, "services not loaded")
	}
	if st := checkBasicIntegrity(cfg, vopts); st != nil {
		return st
	}
	if st := checkExtraIntegrity(cfg, vopts); st != nil {
		return st
	}
	return nil
}

func checkBasicIntegrity(cfg *pb.DamConfig, vopts ValidateCfgOpts) *status.Status {
	for n, ti := range cfg.TrustedIssuers {
		if err := checkName(n); err != nil {
			return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgTrustedPassportIssuer, n), err.Error())
		}
		if !httputils.IsHTTPS(ti.Issuer) && !httputils.IsLocalhost(ti.Issuer) {
			return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgTrustedPassportIssuer, n, "issuer"), "trusted identity must have an issuer of type HTTPS")
		}
		if _, ok := translators[ti.TranslateUsing]; !ok && len(ti.TranslateUsing) > 0 {
			return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgTrustedPassportIssuer, n, "translateUsing"), fmt.Sprintf("trusted identity with unknown translator %q", ti.TranslateUsing))
		}
		if path, err := check.CheckUI(ti.Ui, true); err != nil {
			return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgTrustedPassportIssuer, n, path), fmt.Sprintf("trusted passport issuer UI settings: %v", err))
		}
		if stat := checkTrustedIssuerClientCredentials(n, vopts.DefaultBroker, ti, vopts); stat != nil {
			return stat
		}
	}

	for n, ts := range cfg.TrustedSources {
		if err := checkName(n); err != nil {
			return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgTrustedSources, n), err.Error())
		}
		for i, source := range ts.Sources {
			if !httputils.IsHTTPS(source) {
				return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgTrustedSources, n, "sources", strconv.Itoa(i)), "trusted source URL must be HTTPS")
			}
		}
		for i, visa := range ts.VisaTypes {
			if _, ok := cfg.VisaTypes[visa]; !ok {
				return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgTrustedSources, n, "claims", strconv.Itoa(i)), fmt.Sprintf("visa name %q not found in visa type definitions", visa))
			}
		}
		if path, err := check.CheckUI(ts.Ui, true); err != nil {
			return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgTrustedSources, n, path), fmt.Sprintf("trusted sources UI settings: %v", err))
		}
	}

	for n, policy := range cfg.Policies {
		if err := checkName(n); err != nil {
			return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgPolicies, n), err.Error())
		}
		if path, err := validator.ValidatePolicy(policy, cfg.VisaTypes, cfg.TrustedSources, nil); err != nil {
			return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgPolicies, n, path), err.Error())
		}
		if path, err := check.CheckUI(policy.Ui, true); err != nil {
			return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgPolicies, n, path), fmt.Sprintf("policies UI settings: %v", err))
		}
		// Note: there is no requirement that built-in policies be present. But if they are, they must not be edited.
		// Regular, non-built-in policies must not use reserved UI labels for built-in policies.
		builtin, ok := BuiltinPolicies[n]
		if ok && !proto.Equal(builtin, policy) {
			return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgPolicies, n), fmt.Sprintf("built-in policy cannot be edited"))
		}
		if !ok && policy.Ui["source"] != "" {
			return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgPolicies, n, "ui", "source"), fmt.Sprintf("%q label is reserved for built-in policies", "source"))
		}
		if !ok && policy.Ui["edit"] != "" {
			return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgPolicies, n, "ui", "edit"), fmt.Sprintf("%q label is reserved for built-in policies", "edit"))
		}
	}

	for n, st := range cfg.ServiceTemplates {
		if stat := checkServiceTemplate(n, st, cfg, vopts); stat != nil {
			return stat
		}
	}

	for n, res := range cfg.Resources {
		if err := checkName(n); err != nil {
			return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgResources, n), err.Error())
		}
		for i, item := range res.Clients {
			if _, ok := cfg.Clients[item]; !ok {
				return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgResources, n, "clients", strconv.Itoa(i)), fmt.Sprintf("client %q does not exist", item))
			}
		}
		if len(res.MaxTokenTtl) > 0 && !ttlRE.Match([]byte(res.MaxTokenTtl)) {
			return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgResources, n, "maxTokenTtl"), "max token TTL invalid format")
		}
		for vn, view := range res.Views {
			if stat := checkViewIntegrity(vn, view, n, res, cfg, vopts); stat != nil {
				return stat
			}
		}
		if path, err := check.CheckUI(res.Ui, true); err != nil {
			return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgResources, n, path), fmt.Sprintf("resource UI settings: %v", err))
		}
	}

	for n, cl := range cfg.Clients {
		if err := oathclients.CheckClientIntegrity(n, cl); err != nil {
			return status.Convert(err)
		}
	}

	for n, def := range cfg.VisaTypes {
		if path, err := check.CheckUI(def.Ui, true); err != nil {
			return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgVisaTypes, n, path), fmt.Sprintf("claim definitions UI settings: %v", err))
		}
	}

	personaEmail := make(map[string]string)
	for n, tp := range cfg.TestPersonas {
		if err := checkName(n); err != nil {
			return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgTestPersonas, n), err.Error())
		}
		if tp.Passport == nil {
			return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgTestPersonas, n, "passport"), "persona requires a passport")
		}
		tid, err := persona.ToIdentity(context.Background(), n, tp, defaultPersonaScope, "")
		if err != nil {
			return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgTestPersonas, n), fmt.Sprintf("persona to identity: %v", err))
		}
		if len(tid.Issuer) == 0 {
			return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgTestPersonas, n, "passport", "standardClaims", "iss"), "persona requires an issuer")
		}
		if len(tid.Subject) == 0 {
			return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgTestPersonas, n, "passport", "standardClaims", "sub"), "persona requires a subject")
		}
		if pmatch, ok := personaEmail[tid.Subject]; ok {
			return httputils.NewInfoStatus(codes.AlreadyExists, httputils.StatusPath(cfgTestPersonas, n, "passport", "standardClaims", "sub"), fmt.Sprintf("persona subject %q conflicts with test persona %q", tid.Subject, pmatch))
		}
		for i, a := range tp.Passport.Ga4GhAssertions {
			// Test Persona conditions should meet the same criteria as policies that have no variables / arguments.
			policy := &pb.Policy{
				AnyOf: a.AnyOfConditions,
			}
			if path, err := validator.ValidatePolicy(policy, cfg.VisaTypes, cfg.TrustedSources, nil); err != nil {
				path = strings.Replace(path, "anyOf/", "anyOfConditions/", 1)
				return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgTestPersonas, n, "passport", "ga4ghAssertions", strconv.Itoa(i), path), err.Error())
			}
		}
		if path, err := check.CheckUI(tp.Ui, false); err != nil {
			return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgTestPersonas, n, path), fmt.Sprintf("test persona UI settings: %v", err))
		}
		// Checking persona expectations is in checkExtraIntegrity() to give an
		// opportunity for runTests() to catch problems and calculate a ConfigModification
		// response.
	}

	if stat := checkOptionsIntegrity(cfg.Options, vopts); stat != nil {
		return stat
	}

	if path, err := check.CheckUI(cfg.Ui, true); err != nil {
		return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgRoot, path), fmt.Sprintf("root config UI settings: %v", err))
	}

	return nil
}

func checkExtraIntegrity(cfg *pb.DamConfig, vopts ValidateCfgOpts) *status.Status {
	for n, tp := range cfg.TestPersonas {
		for i, access := range tp.Access {
			aparts := strings.Split(access, "/")
			if len(aparts) != 3 {
				return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgTestPersonas, n, "access", strconv.Itoa(i)), "invalid access entry format (expecting 'resourceName/viewName/roleName')")
			}
			rn := aparts[0]
			vn := aparts[1]
			rolename := aparts[2]
			res, ok := cfg.Resources[rn]
			if !ok {
				return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgTestPersonas, n, "access", strconv.Itoa(i), "resource"), fmt.Sprintf("access entry resource %q not found", rn))
			}
			view, ok := res.Views[vn]
			if !ok {
				return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgTestPersonas, n, "access", strconv.Itoa(i), "view"), fmt.Sprintf("access entry view %q not found", vn))
			}
			roleView := makeView(vn, view, res, cfg, vopts.HidePolicyBasis, vopts.Services)
			if roleView.Roles == nil {
				return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgTestPersonas, n, "access", strconv.Itoa(i), "role"), fmt.Sprintf("access entry no roles defined for view %q", vn))
			}
			if _, ok := roleView.Roles[rolename]; !ok {
				return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgTestPersonas, n, "access", strconv.Itoa(i), "role"), fmt.Sprintf("access entry role %q not found on view %q", rolename, vn))
			}
		}
	}
	return nil
}

func checkViewIntegrity(name string, view *pb.View, resName string, res *pb.Resource, cfg *pb.DamConfig, vopts ValidateCfgOpts) *status.Status {
	if err := checkName(name); err != nil {
		return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgResources, resName, "views", name), err.Error())
	}
	if len(view.ServiceTemplate) == 0 {
		return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgResources, resName, "views", name, "serviceTemplate"), "service template is not defined")
	}
	st, ok := cfg.ServiceTemplates[view.ServiceTemplate]
	if !ok {
		return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgResources, resName, "views", name, "serviceTemplate"), fmt.Sprintf("service template %q not found", view.ServiceTemplate))
	}
	if len(view.Labels) == 0 || view.Labels["version"] == "" {
		return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgResources, resName, "views", name, "metadata", "version"), "version is empty")
	}
	if path, err := checkAccessRequirements(view.ServiceTemplate, st, resName, name, view, cfg, vopts); err != nil {
		return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgResources, resName, path), fmt.Sprintf("access requirements: %v", err))
	}
	if len(view.DefaultRole) == 0 {
		return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgResources, resName, "views", name, "defaultRole"), "default role is empty")
	}
	if _, ok := view.Roles[view.DefaultRole]; !ok {
		return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgResources, resName, "views", name, "defaultRole"), "default role is not defined within the view")
	}
	if len(view.ComputedInterfaces) > 0 {
		return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgResources, resName, "views", name, "interfaces"), "interfaces should be determined at runtime and cannot be stored as part of the config")
	}
	if path, err := check.CheckUI(view.Ui, true); err != nil {
		return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgResources, resName, "views", name, path), fmt.Sprintf("view UI settings: %v", err))
	}

	return nil
}

func checkServiceTemplate(name string, template *pb.ServiceTemplate, cfg *pb.DamConfig, vopts ValidateCfgOpts) *status.Status {
	if err := checkName(name); err != nil {
		return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgServiceTemplates, name), err.Error())
	}
	if len(template.ServiceName) == 0 {
		return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgServiceTemplates, name, "serviceName"), "service is not specified")
	}
	service, ok := vopts.Services.ByServiceName[template.ServiceName]
	if !ok {
		return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgServiceTemplates, name, "serviceName", template.ServiceName), "service is not a recognized by this DAM")
	}
	if path, err := service.CheckConfig(name, template, "", "", nil, cfg, vopts.Services); err != nil {
		return httputils.NewInfoStatus(codes.InvalidArgument, path, err.Error())
	}
	if path, err := checkServiceRoles(template.ServiceRoles, name, template.ServiceName, cfg, vopts); err != nil {
		return httputils.NewInfoStatus(codes.InvalidArgument, path, err.Error())
	}
	varNames := make(map[string]bool)
	desc := vopts.Services.Descriptors[template.ServiceName]
	for varName, v := range desc.ItemVariables {
		varNames[varName] = true
		if v.Type != "const" && v.Type != "split_pattern" {
			return httputils.NewInfoStatus(codes.Internal, httputils.StatusPath("serviceDescriptors", template.ServiceName, "itemVariables", varName, "type"), fmt.Sprintf("variable type %q must be %q or %q", v.Type, "const", "split_pattern"))
		}
	}
	for k, v := range template.Interfaces {
		match := interfaceRE.FindAllString(v, -1)
		for _, varMatch := range match {
			// Remove the `${` prefix and `}` suffix.
			varName := varMatch[2 : len(varMatch)-1]
			if _, ok := varNames[varName]; !ok {
				return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgServiceTemplates, name, "interfaces", k), fmt.Sprintf("interface %q variable %q not defined for this service", k, varName))
			}
		}
	}
	if path, err := check.CheckUI(template.Ui, true); err != nil {
		return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgServiceTemplates, name, path), fmt.Sprintf("service template UI settings: %v", err))
	}
	return nil
}

func checkAccessRequirements(templateName string, template *pb.ServiceTemplate, resName, viewName string, view *pb.View, cfg *pb.DamConfig, vopts ValidateCfgOpts) (string, error) {
	adapt, ok := vopts.Services.ByServiceName[template.ServiceName]
	if !ok {
		return httputils.StatusPath("services"), fmt.Errorf("service template %q service %q is not a recognized by this DAM", templateName, template.ServiceName)
	}
	if path, err := adapt.CheckConfig(templateName, template, resName, viewName, view, cfg, vopts.Services); err != nil {
		return path, err
	}
	if path, err := checkAccessRoles(view.Roles, templateName, template.ServiceName, cfg, vopts); err != nil {
		return httputils.StatusPath("views", viewName, "roles", path), fmt.Errorf("invalid view: %v", err)
	}
	desc, ok := vopts.Services.Descriptors[template.ServiceName]
	if !ok {
		return httputils.StatusPath("services", template.ServiceName), fmt.Errorf("internal error: service %q does not have a service descriptor", template.ServiceName)
	}
	if len(desc.ItemVariables) > 0 && len(view.Items) == 0 {
		return httputils.StatusPath("views", viewName, "items"), fmt.Errorf("view %q does not provide any target items", viewName)
	}
	if len(desc.ItemVariables) > 0 && desc.Properties != nil && desc.Properties.SingleItem && len(view.Items) > 1 {
		return httputils.StatusPath("views", viewName, "items"), fmt.Errorf("view %q provides more than one item when only one was expected for service %q", viewName, template.ServiceName)
	}
	for idx, item := range view.Items {
		vars, path, err := adapter.GetItemVariables(vopts.Services, template.ServiceName, item)
		if err != nil {
			return httputils.StatusPath("views", viewName, "items", strconv.Itoa(idx), path), err
		}
		if len(vars) == 0 {
			return httputils.StatusPath("views", viewName, "items", strconv.Itoa(idx), "vars"), fmt.Errorf("no variables defined")
		}
	}
	return "", nil
}

func checkAccessRoles(roles map[string]*pb.ViewRole, templateName, serviceName string, cfg *pb.DamConfig, vopts ValidateCfgOpts) (string, error) {
	if len(roles) == 0 {
		return "", fmt.Errorf("a view must have at least one role with a selected policy")
	}
	desc := vopts.Services.Descriptors[serviceName]
	for rname, role := range roles {
		if err := checkName(rname); err != nil {
			return httputils.StatusPath(rname), fmt.Errorf("role has invalid name %q: %v", rname, err)
		}
		if len(role.ComputedPolicyBasis) > 0 {
			return httputils.StatusPath(rname, "roleCategories"), fmt.Errorf("role %q roleCategories should be determined at runtime and cannot be stored as part of the config", rname)
		}
		if len(role.ComputedPolicyBasis) > 0 {
			return httputils.StatusPath(rname, "policyBasis"), fmt.Errorf("role %q policyBasis should be determined at runtime and cannot be stored as part of the config", rname)
		}
		if len(role.Policies) > 20 {
			return httputils.StatusPath(rname, "policies"), fmt.Errorf("role exceeeds policy limit")
		}
		hasAllowlist := false
		for i, p := range role.Policies {
			if len(p.Name) == 0 {
				return httputils.StatusPath(rname, "policies", strconv.Itoa(i), "name"), fmt.Errorf("access policy name is not defined")
			}
			if p.Name == allowlistPolicyName {
				hasAllowlist = true
				emails := strings.Split(p.Args["users"], ";")
				if len(emails) > 20 {
					return httputils.StatusPath(rname, "policies", strconv.Itoa(i), "args", "users"), fmt.Errorf("number of emails on allowlist policy exceeeds limit")
				}
				for j, email := range emails {
					if _, err := mail.ParseAddress(email); err != nil {
						return httputils.StatusPath(rname, "policies", strconv.Itoa(i), "args", "users"), fmt.Errorf("email entry %d (%q) is invalid", j, email)
					}
				}
			}
			policy, ok := cfg.Policies[p.Name]
			if !ok {
				return httputils.StatusPath(rname, "policies", strconv.Itoa(i), "name"), fmt.Errorf("policy %q is not defined", p.Name)
			}
			if path, err := validator.ValidatePolicy(policy, cfg.VisaTypes, cfg.TrustedSources, p.Args); err != nil {
				return httputils.StatusPath(rname, "policies", strconv.Itoa(i), path), err
			}
		}
		if len(role.Policies) == 0 && !desc.Properties.IsAggregate {
			return httputils.StatusPath(rname, "policies"), fmt.Errorf("must provide at least one target policy")
		}
		if hasAllowlist && len(role.Policies) > 1 {
			return httputils.StatusPath(rname, "policies"), fmt.Errorf("allowlist policies cannot be used in combination with any other policies")
		}
	}
	return "", nil
}

func checkServiceRoles(roles map[string]*pb.ServiceRole, templateName, serviceName string, cfg *pb.DamConfig, vopts ValidateCfgOpts) (string, error) {
	if len(roles) == 0 {
		return httputils.StatusPath(cfgServiceTemplates, templateName, "roles"), fmt.Errorf("no roles provided")
	}
	desc := vopts.Services.Descriptors[serviceName]
	for rname, role := range roles {
		if err := checkName(rname); err != nil {
			return httputils.StatusPath(cfgServiceTemplates, templateName, "roles", rname), fmt.Errorf("role has invalid name %q: %v", rname, err)
		}
		if len(role.DamRoleCategories) == 0 {
			return httputils.StatusPath(cfgServiceTemplates, templateName, "roles", rname, "damRoleCategories"), fmt.Errorf("role %q does not provide a DAM role category", rname)
		}
		for i, pt := range role.DamRoleCategories {
			if _, ok := vopts.RoleCategories[pt]; !ok {
				return httputils.StatusPath(
						cfgServiceTemplates, templateName, "roles", rname, "damRoleCategories", strconv.Itoa(i)),
					fmt.Errorf("role %q DAM role category %q is not defined (valid types are: %s)", rname, pt,
						strings.Join(roleCategorySet(vopts.RoleCategories), ", "))
			}
		}
		for vname, def := range desc.ServiceVariables {
			arg, ok := role.ServiceArgs[vname]
			if !ok {
				if def.Optional {
					continue
				}
				return httputils.StatusPath(cfgServiceTemplates, templateName, "roles", rname, "serviceArgs", vname), fmt.Errorf("missing required service argument %q", vname)
			}
			re, err := regexp.Compile(def.Regexp)
			if err != nil {
				return httputils.StatusPath("services", templateName, "serviceArgs", vname), fmt.Errorf("variable format regexp %q is not a valid regular expression", def.Regexp)
			}
			for ival, val := range arg.Values {
				if len(val) == 0 {
					return httputils.StatusPath(cfgServiceTemplates, templateName, "roles", rname, "serviceArgs", vname, "values", strconv.Itoa(ival)), fmt.Errorf("service argument value %d is empty", ival)
				}
				if !re.MatchString(val) {
					return httputils.StatusPath(cfgServiceTemplates, templateName, "roles", rname, "serviceArgs", vname, "values", strconv.Itoa(ival)), fmt.Errorf("service argument value %q is not valid", val)
				}
			}
		}
		for aname := range role.ServiceArgs {
			if _, ok := desc.ServiceVariables[aname]; !ok {
				return httputils.StatusPath(cfgServiceTemplates, templateName, "roles", rname, "serviceArgs", aname), fmt.Errorf("service argument name %q is not a known input for service %q", aname, serviceName)
			}
		}
		if path, err := check.CheckUI(role.Ui, true); err != nil {
			return httputils.StatusPath(cfgServiceTemplates, templateName, "roles", rname, path), fmt.Errorf("role %q: %v", rname, err)
		}
	}
	return "", nil
}

func checkOptionsIntegrity(opts *pb.ConfigOptions, vopts ValidateCfgOpts) *status.Status {
	if opts == nil {
		return nil
	}
	// Get the descriptors.
	opts = makeConfigOptions(opts)
	if err := check.CheckIntOption(opts.AwsManagedKeysPerIamUser, "awsManagedKeysPerIamUser", opts.ComputedDescriptors); err != nil {
		return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgOptions, "awsManagedKeysPerIamUser"), err.Error())
	}
	if err := check.CheckStringOption(opts.GcpManagedKeysMaxRequestedTtl, "gcpManagedKeysMaxRequestedTtl", opts.ComputedDescriptors); err != nil {
		return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgOptions, "gcpManagedKeysMaxRequestedTtl"), err.Error())
	}
	if err := check.CheckIntOption(opts.GcpManagedKeysPerAccount, "gcpManagedKeysPerAccount", opts.ComputedDescriptors); err != nil {
		return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgOptions, "gcpManagedKeysPerAccount"), err.Error())
	}
	if err := check.CheckStringOption(opts.GcpServiceAccountProject, "gcpServiceAccountProject", opts.ComputedDescriptors); err != nil {
		return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgOptions, "gcpServiceAccountProject"), err.Error())
	}
	if err := check.CheckStringOption(opts.GcpIamBillingProject, "gcpIamBillingProject", opts.ComputedDescriptors); err != nil {
		return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgOptions, "gcpIamBillingProject"), err.Error())
	}
	return nil
}

func configCheckIntegrity(cfg *pb.DamConfig, mod *pb.ConfigModification, r *http.Request, vopts ValidateCfgOpts) *status.Status {
	bad := codes.InvalidArgument
	if err := check.ValidToWriteConfig(getRealm(r), cfg.Options.ReadOnlyMasterRealm); err != nil {
		return httputils.NewStatus(bad, err.Error())
	}
	if len(cfg.Version) == 0 {
		return httputils.NewStatus(bad, "missing config version")
	}
	if cfg.Revision <= 0 {
		return httputils.NewStatus(bad, "invalid config revision")
	}
	if err := configRevision(mod, cfg); err != nil {
		return httputils.NewStatus(bad, err.Error())
	}
	if stat := updateTests(cfg, mod, vopts); stat != nil {
		return stat
	}
	if stat := checkBasicIntegrity(cfg, vopts); stat != nil {
		return stat
	}
	if tests := runTests(r.Context(), cfg, nil, vopts); hasTestError(tests) {
		stat := httputils.NewStatus(codes.FailedPrecondition, tests.Error)
		return httputils.AddStatusDetails(stat, tests.Modification)
	}
	if stat := checkExtraIntegrity(cfg, vopts); stat != nil {
		return stat
	}
	return nil
}

func checkTrustedIssuerClientCredentials(name, defaultBroker string, tpi *pb.TrustedIssuer, vopts ValidateCfgOpts) *status.Status {
	if name != defaultBroker {
		return nil
	}
	if len(tpi.AuthUrl) == 0 {
		return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgTrustedPassportIssuer, name, "authUrl"), "AuthUrl not provided")
	}
	if len(tpi.TokenUrl) == 0 {
		return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgTrustedPassportIssuer, name, "tokenUrl"), "TokenUrl not provided")
	}
	return nil
}

func checkTrustedIssuer(iss string, cfg *pb.DamConfig, vopts ValidateCfgOpts) *status.Status {
	if len(iss) == 0 {
		return httputils.NewStatus(codes.PermissionDenied, "unauthorized missing passport issuer")
	}
	foundIssuer := false
	for _, ti := range cfg.TrustedIssuers {
		if iss == ti.Issuer {
			foundIssuer = true
			break
		}
	}
	if !foundIssuer {
		return httputils.NewStatus(codes.PermissionDenied, fmt.Sprintf("unauthorized passport issuer %q", iss))
	}
	return nil
}

func rmTestResource(cfg *pb.DamConfig, name string) {
	prefix := name + "/"
	for _, p := range cfg.TestPersonas {
		p.Access = strutil.FilterStringsByPrefix(p.Access, prefix)
	}
}

func rmTestView(cfg *pb.DamConfig, resName, viewName string) {
	prefix := resName + "/" + viewName + "/"
	for _, p := range cfg.TestPersonas {
		p.Access = strutil.FilterStringsByPrefix(p.Access, prefix)
	}
}

func updateTests(cfg *pb.DamConfig, modification *pb.ConfigModification, vopts ValidateCfgOpts) *status.Status {
	if modification == nil {
		return nil
	}
	for name, td := range modification.TestPersonas {
		p, ok := cfg.TestPersonas[name]
		if !ok {
			return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgTestPersonas, name), fmt.Sprintf("test persona %q not found", name))
		}
		p.Access = td.Access
		sort.Strings(p.Access)
	}
	return nil
}

func runTests(ctx context.Context, cfg *pb.DamConfig, resources []string, vopts ValidateCfgOpts) *pb.GetTestResultsResponse {
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
		status, got, rejectedVisas, err := testPersona(ctx, pname, resources, cfg, vopts)
		e := ""
		if err == nil {
			passed++
		} else {
			e = err.Error()
		}
		results = append(results, &pb.GetTestResultsResponse_TestResult{
			Name:          pname,
			Result:        status,
			Access:        got,
			RejectedVisas: makeRejectedVisas(rejectedVisas),
			Error:         e,
		})
		calculateModification(pname, p.Access, got, modification, vopts)
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

func makeRejectedVisas(rejected []*ga4gh.RejectedVisa) []*pb.GetTestResultsResponse_RejectedVisa {
	if len(rejected) == 0 {
		return nil
	}
	out := []*pb.GetTestResultsResponse_RejectedVisa{}
	for _, reject := range rejected {
		out = append(out, &pb.GetTestResultsResponse_RejectedVisa{
			Reason:      reject.Rejection.Reason,
			Field:       reject.Rejection.Field,
			Description: reject.Rejection.Description,
			VisaType:    string(reject.Assertion.Type),
			Source:      string(reject.Assertion.Source),
			Value:       string(reject.Assertion.Value),
			By:          string(reject.Assertion.By),
		})
	}
	return out
}

func hasTestError(tr *pb.GetTestResultsResponse) bool {
	return len(tr.Error) > 0
}

func calculateModification(name string, want []string, got []string, modification *pb.ConfigModification, vopts ValidateCfgOpts) {
	entry, ok := modification.TestPersonas[name]
	if !ok {
		entry = &pb.ConfigModification_PersonaModification{
			Access:       got,
			AddAccess:    []string{},
			RemoveAccess: []string{},
		}
		modification.TestPersonas[name] = entry
	}
	deltaResourceModification(entry, want, got, vopts)
	if len(entry.AddAccess) == 0 && len(entry.RemoveAccess) == 0 {
		delete(modification.TestPersonas, name)
	}
}

func deltaResourceModification(entry *pb.ConfigModification_PersonaModification, want []string, got []string, vopts ValidateCfgOpts) bool {
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
