package authorization

import (
	"fmt"

	"github.com/brancz/kube-rbac-proxy/pkg/authorization/path"
	"github.com/brancz/kube-rbac-proxy/pkg/authorization/rewrite"
	"github.com/brancz/kube-rbac-proxy/pkg/authorization/static"
	"github.com/brancz/kube-rbac-proxy/pkg/server"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/union"
	serverconfig "k8s.io/apiserver/pkg/server"
)

func setupAuthorizer(krbInfo *server.KubeRBACProxyInfo, delegatedAuthz *serverconfig.AuthorizationInfo) (authorizer.Authorizer, error) {
	staticAuthorizer, err := static.NewStaticAuthorizer(krbInfo.Authorization.Static)
	if err != nil {
		return nil, fmt.Errorf("failed to create static authorizer: %w", err)
	}

	var authz authorizer.Authorizer = rewrite.NewRewritingAuthorizer(
		union.New(
			staticAuthorizer,
			delegatedAuthz.Authorizer,
		),
		krbInfo.Authorization.RewriteAttributesConfig,
	)

	if allowPaths := krbInfo.AllowPaths; len(allowPaths) > 0 {
		authz = union.New(path.NewAllowPathAuthorizer(allowPaths), authz)
	}

	if ignorePaths := krbInfo.IgnorePaths; len(ignorePaths) > 0 {
		authz = union.New(path.NewAlwaysAllowPathAuthorizer(ignorePaths), authz)
	}

	return authz, nil
}
