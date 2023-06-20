/*
Copyright 2023 the kube-rbac-proxy maintainers. All rights reserved.

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
	"context"
	"fmt"

	"k8s.io/apiserver/pkg/authorization/authorizer"
)

var _ authorizer.Authorizer = &ressourceBoundAuthorizer{}

func NewRessourceBoundAuthorizer(delegate authorizer.Authorizer, config *RewriteAttributesConfig) authorizer.Authorizer {
	return &ressourceBoundAuthorizer{
		config:   config,
		delegate: delegate,
	}
}

// ressourceBoundAuthorizer is an authorizer that rewrites the attributes of a
// request such that the request is authorized against the rewritten attributes,
// which are defined in the configuration.
type ressourceBoundAuthorizer struct {
	config   *RewriteAttributesConfig
	delegate authorizer.Authorizer
}

// GetRequestAttributes populates authorizer attributes for the requests to kube-rbac-proxy.
func (n *ressourceBoundAuthorizer) Authorize(ctx context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
	u := attrs.GetUser()
	apiVerb := attrs.GetVerb()

	proxyAttrs := authorizer.AttributesRecord{
		User:            u,
		Verb:            apiVerb,
		Namespace:       n.config.ResourceAttributes.Namespace,
		APIGroup:        n.config.ResourceAttributes.APIGroup,
		APIVersion:      n.config.ResourceAttributes.APIVersion,
		Resource:        n.config.ResourceAttributes.Resource,
		Subresource:     n.config.ResourceAttributes.Subresource,
		Name:            n.config.ResourceAttributes.Name,
		ResourceRequest: true,
	}

	var (
		authorized authorizer.Decision
		reason     string
		err        error
	)

	authorized, reason, err = n.delegate.Authorize(ctx, proxyAttrs)
	if err != nil {
		return authorizer.DecisionDeny,
			"AuthorizationError",
			fmt.Errorf("authorization error (user=%s, verb=%s, resource=%s, subresource=%s): %w", proxyAttrs.GetName(), proxyAttrs.GetVerb(), proxyAttrs.GetResource(), proxyAttrs.GetSubresource(), err)
	}
	if authorized != authorizer.DecisionAllow {
		return authorizer.DecisionDeny,
			fmt.Sprintf("Forbidden (user=%s, verb=%s, resource=%s, subresource=%s): %s", proxyAttrs.GetName(), proxyAttrs.GetVerb(), proxyAttrs.GetResource(), proxyAttrs.GetSubresource(), reason),
			nil
	}

	if authorized == authorizer.DecisionAllow {
		return authorized, "", nil
	}

	return authorizer.DecisionDeny,
		"No attribute combination matched",
		nil
}
