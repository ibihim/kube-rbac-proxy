package rewrite

import (
	"bytes"
	"context"
	"text/template"

	"k8s.io/apiserver/pkg/authorization/authorizer"
)

// DefaultAttributesGenerator is an AttributesGenerator that generates a list of
// attributes that are used to authorize a request.
//
// It focuses on user and http based attributes.
type DefaultAttributesGenerator struct{}

// Generate implements AttributesGenerator. It generates a list of Attributes.
// The list contains one AttributesRecord that reduces the original attributes
// to user and http based attributes.
func (d *DefaultAttributesGenerator) Generate(ctx context.Context, attr authorizer.Attributes) []authorizer.Attributes {
	return []authorizer.Attributes{
		authorizer.AttributesRecord{
			User:            attr.GetUser(),
			Verb:            attr.GetVerb(),
			ResourceRequest: false,
			Path:            attr.GetPath(),
		},
	}
}

// BoundAttributesGenerator is an AttributesGenerator that generates a list of
// attributes that are used to authorize a request.
//
// It uses the given Attributes' user and http verb and verifies its
// authorization against a predefined kubernetes resource. The authorization is
// bound to that given kubernetes resource.
type BoundAttributesGenerator struct {
	attributes *ResourceAttributes
}

// NewBoundAttributesGenerator returns a BoundAttributesGenerator that uses the
// given ResourceAttributes to generate a list of attributes that are used to
// authorize a request.
func NewBoundAttributesGenerator(attributes *ResourceAttributes) *BoundAttributesGenerator {
	return &BoundAttributesGenerator{
		attributes: attributes,
	}
}

// Generate implements AttributesGenerator. It generates a list of Attributes.
// The list contains one AttributesRecord that references a target kubernetes
// resource, but it uses the original attributes' user and http verb.
func (b *BoundAttributesGenerator) Generate(ctx context.Context, attr authorizer.Attributes) []authorizer.Attributes {
	return []authorizer.Attributes{
		authorizer.AttributesRecord{
			User:            attr.GetUser(),
			Verb:            attr.GetVerb(),
			Namespace:       b.attributes.Namespace,
			APIGroup:        b.attributes.APIGroup,
			APIVersion:      b.attributes.APIVersion,
			Resource:        b.attributes.Resource,
			Subresource:     b.attributes.Subresource,
			Name:            b.attributes.Name,
			ResourceRequest: true,
		},
	}
}

// RewritingAttributesGenerator is an AttributesGenerator that generates a list
// of attributes that are used to authorize a request.
//
// It uses the given Attributes' user and http verb and verifies its
// authorization against a predefined kubernetes resource template. The template
// is rewritting using client input data, which is VERY DANGEROUS and should
// not be used unless the upstream service behind kube-rbac-proxy interprets
// the template values as well.
type RewritingAttributesGenerator struct {
	attributes *ResourceAttributes
}

// NewRewritingAttributesGenerator returns a RewritingAttributesGenerator that
// uses the given ResourceAttributes to generate a list of attributes that are
// used to authorize a request.
func NewRewritingAttributesGenerator(attributes *ResourceAttributes) *RewritingAttributesGenerator {
	return &RewritingAttributesGenerator{
		attributes: attributes,
	}
}

// Generate implements AttributesGenerator. It generates a list of Attributes.
// The list contains one AttributesRecord that references a templated target
// kubernetes resource. It uses the original attributes' user and http verb.
// The template is rewritten using client input data, which is VERY DANGEROUS
// and should only be used when the upstream service behind kube-rbac-proxy
// interprets the template values as well.
func (r *RewritingAttributesGenerator) Generate(ctx context.Context, attr authorizer.Attributes) []authorizer.Attributes {
	params := GetKubeRBACProxyParams(ctx)
	if len(params) == 0 {
		return nil
	}

	attrs := []authorizer.Attributes{}
	for _, param := range params {
		attrs = append(attrs,
			authorizer.AttributesRecord{
				User:            attr.GetUser(),
				Verb:            attr.GetVerb(),
				Namespace:       templateWithValue(r.attributes.Namespace, param),
				APIGroup:        templateWithValue(r.attributes.APIGroup, param),
				APIVersion:      templateWithValue(r.attributes.APIVersion, param),
				Resource:        templateWithValue(r.attributes.Resource, param),
				Subresource:     templateWithValue(r.attributes.Subresource, param),
				Name:            templateWithValue(r.attributes.Name, param),
				ResourceRequest: true,
			})
	}

	return attrs
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
