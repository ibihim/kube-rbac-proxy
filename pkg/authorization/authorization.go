package authorization

import (
	"fmt"

	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/union"
	serverconfig "k8s.io/apiserver/pkg/server"

	"github.com/brancz/kube-rbac-proxy/pkg/authorization/path"
	"github.com/brancz/kube-rbac-proxy/pkg/authorization/rewrite"
	"github.com/brancz/kube-rbac-proxy/pkg/authorization/static"
)

func SetupAuthorizer(
	config *AuthzConfig,
	allowPaths []string,
	ignorePaths []string,
	delegate *serverconfig.AuthorizationInfo,
) (authorizer.Authorizer, error) {
	var authz []authorizer.Authorizer

	// Allow and ignore paths are mutually exclusive.
	// AllowPaths denies access to paths that are not listed.
	// IgnorePaths doesn't auth(n/z) paths that are listed.
	switch {
	case len(allowPaths) > 0 && len(ignorePaths) > 0:
		return nil, fmt.Errorf("allow and ignore paths cannot be used together")
	case len(allowPaths) > 0:
		authz = append(authz, path.NewAllowPathAuthorizer(allowPaths))
	case len(ignorePaths) > 0:
		authz = append(authz, path.NewAlwaysAllowPathAuthorizer(ignorePaths))
	}

	// Static authorization authorizes against a static file.
	if config.Static != nil {
		staticAuthorizer, err := static.NewStaticAuthorizer(config.Static)
		if err != nil {
			return nil, fmt.Errorf("failed to create static authorizer: %w", err)
		}

		authz = append(authz, staticAuthorizer)
	}

	// As a final resort, delegate to the kubernetes apiserver with a
	// SubjectAccessReview.
	delegatedAuthz := union.New(
		append(authz, delegate.Authorizer)...,
	)

	// Rewriting attributes that they fit the given use-case.
	var attrsGenerator rewrite.AttributesGenerator
	switch {
	case config.ResourceAttributes != nil && config.Rewrites == nil:
		attrsGenerator = rewrite.NewBoundAttributesGenerator(
			config.ResourceAttributes,
		)
	case config.ResourceAttributes != nil && config.Rewrites != nil:
		attrsGenerator = rewrite.NewRewritingAttributesGenerator(
			config.ResourceAttributes,
		)
	default:
		attrsGenerator = &rewrite.DefaultAttributesGenerator{}
	}

	return rewrite.NewDelegateAuthorizer(delegatedAuthz, attrsGenerator), nil
}
