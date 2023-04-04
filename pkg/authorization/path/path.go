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

package path

import (
	"context"
	"path"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

type pathAuthorizer struct {
	matchDecision, noMatchDecision authorizer.Decision

	paths        sets.String
	pathPatterns []string
}

var noopAuthorizer = authorizer.AuthorizerFunc(
	func(context.Context, authorizer.Attributes) (authorizer.Decision, string, error) {
		return authorizer.DecisionNoOpinion, "", nil
	},
)

func newPathAuthorizer(onMatch, onNoMatch authorizer.Decision, inputPaths []string) *pathAuthorizer {
	var patterns []string
	paths := sets.NewString() // faster than trying to match every pattern every time

	for _, p := range inputPaths {
		p = strings.TrimPrefix(p, "/")
		if len(p) == 0 {
			// matches "/"
			paths.Insert(p)
			continue
		}

		if strings.ContainsRune(p, '*') {
			patterns = append(patterns, p)
			continue
		}

		paths.Insert(p)
	}

	return &pathAuthorizer{
		matchDecision:   onMatch,
		noMatchDecision: onNoMatch,
		paths:           paths,
		pathPatterns:    patterns,
	}
}

func (a *pathAuthorizer) Authorize(ctx context.Context, attr authorizer.Attributes) (authorizer.Decision, string, error) {
	pth := strings.TrimPrefix(attr.GetPath(), "/")
	if a.paths.Has(pth) {
		return a.matchDecision, "", nil
	}

	for _, pattern := range a.pathPatterns {
		found, err := path.Match(pattern, pth)
		if err != nil {
			return authorizer.DecisionNoOpinion, "Error", err
		}
		if found {
			return a.matchDecision, "", nil
		}
	}

	return a.noMatchDecision, "", nil
}

// NewAllowPathAuthorizer denies access to any path not in the allowed paths list.
func NewAllowPathAuthorizer(allowPaths []string) authorizer.Authorizer {
	if len(allowPaths) == 0 {
		return noopAuthorizer
	}

	return newPathAuthorizer(authorizer.DecisionNoOpinion, authorizer.DecisionDeny, allowPaths)
}

// NewAlwaysAllowPathAuthorizer allows access to any path in the allowed paths list.
func NewAlwaysAllowPathAuthorizer(alwaysAllowPaths []string) authorizer.Authorizer {
	return newPathAuthorizer(authorizer.DecisionAllow, authorizer.DecisionNoOpinion, alwaysAllowPaths)
}
