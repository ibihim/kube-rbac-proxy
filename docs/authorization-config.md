# Autorization Configuration

## Static Authorization

Static authorization allows requests to pass through if the given
`authorizer.Attributes` match a predefined set of rules. It is **important** to
note that unset attributes are considered as **pass-through**.

## Rewrites

Rewrites are used when an upstream service offers global resources, and a client
wants to access resources within their own domain of authority.
Therefore an authoziation against another `resourceAttributes` than the actual
ones, might make sense.

### ResourceAttributes

- If no `resourceAttributes` are specified, the attributes remain unmodified.
- If `resourceAttributes` are specified, but `rewrites` are not, they overwrite
  the request's attributes.
- If `resourceAttributes` and `rewrites` are specified, it is assumed, that the
  `resourceAttributes` are templates to be filled with the `rewrite` values.

### ResourceAttributes

- If no `resourceAttributes` are specified, the attributes remain unmodified.
- If both `resourceAttributes` and `rewrites` are specified, it is assumed that
  the `resourceAttributes` are templates to be filled with the `rewrite` values.
- If `resourceAttributes` are specified and `rewrites` are not, they overwrite
  the request's attributes in its static form.

#### Template-based Rewriting

Template-based rewriting enables dynamic substitution of values from rewrite
parameters into the resource attributes. The substitution occurs for the
configured keys of `Queries` or `Headers`, replacing them with their
corresponding values.

## Example

Monitoring rewrites examples:

```yaml
authorization:
  resourceAttributes:
    apiGroup: monitoring.coreos.com
    namespace: {{ .Value }}
    resource: prometheusrules
  rewrites:
    byQueryParameter:
      name: namespace
```

```yaml
authorization:
  rewrites:
    byQueryParameter:
      name: "namespace"
  resourceAttributes:
    apiVersion: v1
    resource: namespace
    subresource: metrics
    namespace: "{{ .Value }}"
  static:
    - resourceRequest: true
      resource: namespace
      subresource: metrics
```

Static example:

```yaml
authorization:
  static:
    - user:
        name: alice
        groups:
          - development
          - staging
      verb: get
      namespace: my-namespace
      apiGroup: apps
      resource: deployments
      name: my-deployment
      resourceRequest: true
      path: /access/for/alice/from/my-namespace
```

### References

- **Rewrite PR**: [*: Add rewrite functionality of SubjectAccessReview requests #17](https://github.com/brancz/kube-rbac-proxy/pull/17)

