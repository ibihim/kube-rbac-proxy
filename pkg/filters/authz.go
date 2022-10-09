package filters

import (
	"fmt"
	"net/http"

	"github.com/brancz/kube-rbac-proxy/pkg/authz"

	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/klog/v2"
)

func WithAuthorization(
	handler http.Handler,
	authz authorizer.Authorizer,
	cfg *authz.Config,
) http.Handler {
	authzAttrGetter := cfg.GetRequestAttributes

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		u, ok := request.UserFrom(req.Context())
		if !ok {
			http.Error(w, "user not in context", http.StatusUnauthorized)
			return
		}

		allAttrs := authzAttrGetter(u, req)
		if len(allAttrs) == 0 {
			msg := "Bad Request. The request or configuration is malformed."
			klog.V(2).Info(msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}

		for _, attrs := range allAttrs {
			// Authorize
			authorized, reason, err := authz.Authorize(req.Context(), attrs)
			if err != nil {
				msg := fmt.Sprintf("Authorization error (user=%s, verb=%s, resource=%s, subresource=%s)", u.GetName(), attrs.GetVerb(), attrs.GetResource(), attrs.GetSubresource())
				klog.Errorf("%s: %s", msg, err)
				http.Error(w, msg, http.StatusInternalServerError)
				return
			}
			if authorized != authorizer.DecisionAllow {
				msg := fmt.Sprintf("Forbidden (user=%s, verb=%s, resource=%s, subresource=%s)", u.GetName(), attrs.GetVerb(), attrs.GetResource(), attrs.GetSubresource())
				klog.V(2).Infof("%s. Reason: %q.", msg, reason)
				http.Error(w, msg, http.StatusForbidden)
				return
			}
		}

		handler.ServeHTTP(w, req)
	})
}
