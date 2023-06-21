package rewrite

const rewriterParams = iota

// RewriteAttributesConfig holds configuration enabling request authorization
type RewriteAttributesConfig struct {
	Rewrites           *SubjectAccessReviewRewrites `json:"rewrites,omitempty"`
	ResourceAttributes *ResourceAttributes          `json:"resourceAttributes,omitempty"`
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
