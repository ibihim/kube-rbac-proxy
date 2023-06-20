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

package authorization

import (
	"github.com/brancz/kube-rbac-proxy/pkg/authorization/rewrite"
	"github.com/brancz/kube-rbac-proxy/pkg/authorization/static"
)

// ResourceAttributes describes attributes available for resource request authorization
type ResourceAttributes struct {
	Namespace   string `json:"namespace,omitempty"`
	APIGroup    string `json:"apiGroup,omitempty"`
	APIVersion  string `json:"apiVersion,omitempty"`
	Resource    string `json:"resource,omitempty"`
	Subresource string `json:"subresource,omitempty"`
	Name        string `json:"name,omitempty"`
}

// Config holds configuration enabling request authorization
type AuthzConfig struct {
	*rewrite.RewriteAttributesConfig `json:",inline"`
	Static                           []static.StaticAuthorizationConfig `json:"static,omitempty"`
}

const rewriterParams = iota

type RewriteAttributesConfig struct {
	Rewrites           *SubjectAccessReviewRewrites `json:"rewrites,omitempty"`
	ResourceAttributes *ResourceAttributes          `json:"resourceAttributes,omitempty"`
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
