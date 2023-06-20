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

var _ authorizer.Authorizer = &defaultAuthorizer{}

func NewDefaultAuthorizer(delegate authorizer.Authorizer) authorizer.Authorizer {
	return &defaultAuthorizer{
		delegate: delegate,
	}
}

// defaultAuthorizer is an authorizer that delegates to the provided authorizer.
// It generates attributes that validates the HTTP verb, path and user.
type defaultAuthorizer struct {
	delegate authorizer.Authorizer
}

// GetRequestAttributes populates authorizer attributes for the requests to kube-rbac-proxy.
func (n *defaultAuthorizer) Authorize(ctx context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
	u := attrs.GetUser()
	apiVerb := attrs.GetVerb()
	path := attrs.GetPath()

	attrsRecord := authorizer.AttributesRecord{
		User:            u,
		Verb:            apiVerb,
		ResourceRequest: false,
		Path:            path,
	}

	var (
		authorized authorizer.Decision
		reason     string
		err        error
	)

	authorized, reason, err = n.delegate.Authorize(ctx, attrsRecord)
	if err != nil {
		return authorizer.DecisionDeny,
			"AuthorizationError",
			fmt.Errorf(
				"authorization error (user=%s, verb=%s, resource=%s, subresource=%s): %w",
				attrsRecord.GetName(), attrsRecord.GetVerb(), attrsRecord.GetResource(), attrsRecord.GetSubresource(),
				err,
			)
	}

	if authorized != authorizer.DecisionAllow {
		return authorizer.DecisionDeny,
			fmt.Sprintf(
				"Forbidden (user=%s, verb=%s, resource=%s, subresource=%s): %s",
				attrsRecord.GetName(), attrsRecord.GetVerb(), attrsRecord.GetResource(), attrsRecord.GetSubresource(),
				reason,
			),
			nil
	}

	if authorized == authorizer.DecisionAllow {
		return authorized, "", nil
	}

	return authorizer.DecisionDeny,
		"No attribute combination matched",
		nil
}
