/*
Copyright 2017 Frederic Branczyk Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package authz

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/textproto"
	"time"

	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/authorizerfactory"
	"k8s.io/apiserver/pkg/server/options"
	authorizationclient "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/klog/v2"
)

// Config holds configuration enabling request authorization
type Config struct {
	Rewrites               *SubjectAccessReviewRewrites `json:"rewrites,omitempty"`
	ResourceAttributes     *ResourceAttributes          `json:"resourceAttributes,omitempty"`
	ResourceAttributesFile string                       `json:"-"`
	Static                 []StaticAuthorizationConfig  `json:"static,omitempty"`
}

// GetRequestAttributes populates authorizer attributes for the requests to kube-rbac-proxy.
func (c Config) GetRequestAttributes(u user.Info, r *http.Request) []authorizer.Attributes {
	apiVerb := "*"
	switch r.Method {
	case "POST":
		apiVerb = "create"
	case "GET":
		apiVerb = "get"
	case "PUT":
		apiVerb = "update"
	case "PATCH":
		apiVerb = "patch"
	case "DELETE":
		apiVerb = "delete"
	}

	var allAttrs []authorizer.Attributes

	defer func() {
		for attrs := range allAttrs {
			klog.V(5).Infof("kube-rbac-proxy request attributes: attrs=%#+v", attrs)
		}
	}()

	if c.ResourceAttributes == nil {
		// Default attributes mirror the API attributes that would allow this access to kube-rbac-proxy
		allAttrs := append(allAttrs, authorizer.AttributesRecord{
			User:            u,
			Verb:            apiVerb,
			Namespace:       "",
			APIGroup:        "",
			APIVersion:      "",
			Resource:        "",
			Subresource:     "",
			Name:            "",
			ResourceRequest: false,
			Path:            r.URL.Path,
		})
		return allAttrs
	}

	if c.Rewrites == nil {
		allAttrs := append(allAttrs, authorizer.AttributesRecord{
			User:            u,
			Verb:            apiVerb,
			Namespace:       c.ResourceAttributes.Namespace,
			APIGroup:        c.ResourceAttributes.APIGroup,
			APIVersion:      c.ResourceAttributes.APIVersion,
			Resource:        c.ResourceAttributes.Resource,
			Subresource:     c.ResourceAttributes.Subresource,
			Name:            c.ResourceAttributes.Name,
			ResourceRequest: true,
		})
		return allAttrs
	}

	params := []string{}
	if c.Rewrites.ByQueryParameter != nil && c.Rewrites.ByQueryParameter.Name != "" {
		if ps, ok := r.URL.Query()[c.Rewrites.ByQueryParameter.Name]; ok {
			params = append(params, ps...)
		}
	}
	if c.Rewrites.ByHTTPHeader != nil && c.Rewrites.ByHTTPHeader.Name != "" {
		mimeHeader := textproto.MIMEHeader(r.Header)
		mimeKey := textproto.CanonicalMIMEHeaderKey(c.Rewrites.ByHTTPHeader.Name)
		if ps, ok := mimeHeader[mimeKey]; ok {
			params = append(params, ps...)
		}
	}

	if len(params) == 0 {
		return allAttrs
	}

	for _, param := range params {
		attrs := authorizer.AttributesRecord{
			User:            u,
			Verb:            apiVerb,
			Namespace:       templateWithValue(c.ResourceAttributes.Namespace, param),
			APIGroup:        templateWithValue(c.ResourceAttributes.APIGroup, param),
			APIVersion:      templateWithValue(c.ResourceAttributes.APIVersion, param),
			Resource:        templateWithValue(c.ResourceAttributes.Resource, param),
			Subresource:     templateWithValue(c.ResourceAttributes.Subresource, param),
			Name:            templateWithValue(c.ResourceAttributes.Name, param),
			ResourceRequest: true,
		}
		allAttrs = append(allAttrs, attrs)
	}
	return allAttrs
}

func templateWithValue(templateString, value string) string {
	tmpl, _ := template.New("valueTemplate").Parse(templateString)
	out := bytes.NewBuffer(nil)
	err := tmpl.Execute(out, struct{ Value string }{Value: value})
	if err != nil {
		return ""
	}
	return out.String()
}

// SubjectAccessReviewRewrites describes how SubjectAccessReview may be
// rewritten on a given request.
type SubjectAccessReviewRewrites struct {
	ByQueryParameter *QueryParameterRewriteConfig `json:"byQueryParameter,omitempty"`
	ByHTTPHeader     *HTTPHeaderRewriteConfig     `json:"byHttpHeader,omitempty"`
}

// QueryParameterRewriteConfig describes which HTTP URL query parameter is to
// be used to rewrite a SubjectAccessReview on a given request.
type QueryParameterRewriteConfig struct {
	Name string `json:"name,omitempty"`
}

// HTTPHeaderRewriteConfig describes which HTTP header is to
// be used to rewrite a SubjectAccessReview on a given request.
type HTTPHeaderRewriteConfig struct {
	Name string `json:"name,omitempty"`
}

// ResourceAttributes describes attributes available for resource request authorization
type ResourceAttributes struct {
	Namespace   string `json:"namespace,omitempty"`
	APIGroup    string `json:"apiGroup,omitempty"`
	APIVersion  string `json:"apiVersion,omitempty"`
	Resource    string `json:"resource,omitempty"`
	Subresource string `json:"subresource,omitempty"`
	Name        string `json:"name,omitempty"`
}

// StaticAuthorizationConfig describes what is needed to specify a static
// authorization.
type StaticAuthorizationConfig struct {
	User            UserConfig
	Verb            string `json:"verb,omitempty"`
	Namespace       string `json:"namespace,omitempty"`
	APIGroup        string `json:"apiGroup,omitempty"`
	Resource        string `json:"resource,omitempty"`
	Subresource     string `json:"subresource,omitempty"`
	Name            string `json:"name,omitempty"`
	ResourceRequest bool   `json:"resourceRequest,omitempty"`
	Path            string `json:"path,omitempty"`
}

type UserConfig struct {
	Name   string   `json:"name,omitempty"`
	Groups []string `json:"groups,omitempty"`
}

// NewSarAuthorizer creates an authorizer compatible with the kubelet's needs
func NewSarAuthorizer(client authorizationclient.AuthorizationV1Interface) (authorizer.Authorizer, error) {
	if client == nil {
		return nil, errors.New("no client provided, cannot use webhook authorization")
	}
	authorizerConfig := authorizerfactory.DelegatingAuthorizerConfig{
		SubjectAccessReviewClient: client,
		// Defaults are most probably taken from: kubernetes/pkg/kubelet/apis/config/v1beta1/defaults.go
		// Defaults that are more reasonable: apiserver/pkg/server/options/authorization.go
		AllowCacheTTL:       5 * time.Minute,
		DenyCacheTTL:        30 * time.Second,
		WebhookRetryBackoff: options.DefaultAuthWebhookRetryBackoff(),
	}
	return authorizerConfig.New()
}

type staticAuthorizer struct {
	config []StaticAuthorizationConfig
}

func (saConfig StaticAuthorizationConfig) Matches(a authorizer.Attributes) bool {
	isAllowed := func(staticConf string, requestVal string) bool {
		if staticConf == "" {
			return true
		} else {
			return staticConf == requestVal
		}
	}

	userName := ""
	if a.GetUser() != nil {
		userName = a.GetUser().GetName()
	}

	if isAllowed(saConfig.User.Name, userName) &&
		isAllowed(saConfig.Verb, a.GetVerb()) &&
		isAllowed(saConfig.Namespace, a.GetNamespace()) &&
		isAllowed(saConfig.APIGroup, a.GetAPIGroup()) &&
		isAllowed(saConfig.Resource, a.GetResource()) &&
		isAllowed(saConfig.Subresource, a.GetSubresource()) &&
		isAllowed(saConfig.Name, a.GetName()) &&
		isAllowed(saConfig.Path, a.GetPath()) &&
		saConfig.ResourceRequest == a.IsResourceRequest() {
		return true
	}
	return false
}

func (sa staticAuthorizer) Authorize(ctx context.Context, a authorizer.Attributes) (authorized authorizer.Decision, reason string, err error) {
	// compare a against the configured static auths
	for _, saConfig := range sa.config {
		if saConfig.Matches(a) {
			return authorizer.DecisionAllow, "found corresponding static auth config", nil
		}
	}

	return authorizer.DecisionNoOpinion, "", nil
}

func NewStaticAuthorizer(config []StaticAuthorizationConfig) (*staticAuthorizer, error) {
	for _, c := range config {
		if c.ResourceRequest != (c.Path == "") {
			return nil, fmt.Errorf("invalid configuration: resource requests must not include a path: %v", config)
		}
	}
	return &staticAuthorizer{config}, nil
}
