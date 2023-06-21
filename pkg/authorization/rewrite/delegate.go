package rewrite

import (
	"context"
	"fmt"

	"k8s.io/apiserver/pkg/authorization/authorizer"
)

// AttributesGenerator is a an interface for generating a list of attributes
// based on the given attributes and context.
type AttributesGenerator interface {
	Generate(context.Context, authorizer.Attributes) []authorizer.Attributes
}

// NewDelegateAuthorizer returns an authorizer that delegates to the given
// delegate after generating a list of attributes using the given
// AttributesGenerator.
// The delegate is expected to make a SubjectAccessReview request to the
// API server.
func NewDelegateAuthorizer(delegate authorizer.Authorizer, attrGen AttributesGenerator) authorizer.Authorizer {
	return &delegateAuthorizer{
		delegate: delegate,
		attrGen:  attrGen,
	}
}

type delegateAuthorizer struct {
	delegate authorizer.Authorizer
	attrGen  AttributesGenerator
}

// Authorize implements authorizer.Authorizer. It generates a list of attributes
// using the AttributesGenerator and delegates all of them to the given delegate
// authorizer.
func (a *delegateAuthorizer) Authorize(ctx context.Context, attr authorizer.Attributes) (authorized authorizer.Decision, reason string, err error) {
	attrs := a.attrGen.Generate(ctx, attr)

	// AND logic. "no opinion" is treated as "deny".
	for _, attr := range attrs {
		authorized, reason, err = a.delegate.Authorize(ctx, attr)
		if err != nil {
			return authorizer.DecisionDeny,
				"AuthorizationError",
				fmt.Errorf(
					"authorization error (user=%s, verb=%s, resource=%s, subresource=%s): %w",
					attr.GetName(), attr.GetVerb(), attr.GetResource(), attr.GetSubresource(),
					err,
				)
		}

		if authorized != authorizer.DecisionAllow {
			return authorizer.DecisionDeny,
				fmt.Sprintf(
					"Forbidden (user=%s, verb=%s, resource=%s, subresource=%s): %s",
					attr.GetName(), attr.GetVerb(), attr.GetResource(), attr.GetSubresource(),
					reason,
				),
				nil
		}
	}

	if authorized == authorizer.DecisionAllow {
		return authorized, "", nil
	}

	return authorizer.DecisionDeny, "No attribute combination matched", nil
}
