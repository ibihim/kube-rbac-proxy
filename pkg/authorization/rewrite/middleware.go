package rewrite

import (
	"context"
	"net/http"
	"net/textproto"

	"k8s.io/apiserver/pkg/endpoints/request"
)

// WithKubeRBACProxyParamsHandler returns a handler that adds the params from
// the request to the context from pre-defined locations.
// They can origin from the query parameters or from the HTTP headers.
func WithKubeRBACProxyParamsHandler(handler http.Handler, config *RewriteAttributesConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(
			WithKubeRBACProxyParams(
				r.Context(),
				requestToParams(config, r),
			),
		)

		handler.ServeHTTP(w, r)
	})
}

// requestToParams returns the params from the request that should be used to
// rewrite the attributes.
func requestToParams(config *RewriteAttributesConfig, req *http.Request) []string {
	params := []string{}
	if config == nil || config.Rewrites == nil {
		return nil
	}

	if config.Rewrites.ByQueryParameter != nil && config.Rewrites.ByQueryParameter.Name != "" {
		if ps, ok := req.URL.Query()[config.Rewrites.ByQueryParameter.Name]; ok {
			params = append(params, ps...)
		}
	}

	if config.Rewrites.ByHTTPHeader != nil && config.Rewrites.ByHTTPHeader.Name != "" {
		mimeHeader := textproto.MIMEHeader(req.Header)
		mimeKey := textproto.CanonicalMIMEHeaderKey(config.Rewrites.ByHTTPHeader.Name)
		if ps, ok := mimeHeader[mimeKey]; ok {
			params = append(params, ps...)
		}
	}

	return params
}

// WithKubeRBACProxyParams adds the values from the pre-defined location to the
// context.
func WithKubeRBACProxyParams(ctx context.Context, params []string) context.Context {
	return request.WithValue(ctx, rewriterParams, params)
}

// GetKubeRBACProxyParams returns the values from the context that should be
// used to rewrite the attributes.
func GetKubeRBACProxyParams(ctx context.Context) []string {
	params, ok := ctx.Value(rewriterParams).([]string)
	if !ok {
		return nil
	}
	return params
}
