# Runbook: Merge an Upstream Release into the OpenShift Fork

This runbook is written for AI agents. Humans can follow it too. Execute the
steps in order, in bash. Every step ends with a **Check**. If a check fails or
a **STOP** condition applies, stop and report to the human (see
[Report](#report)). Do not improvise around a STOP. Once the human resolves
it, or tells you to apply the fix you proposed, continue where you stopped.

Past merges for reference: [#146](https://github.com/openshift/kube-rbac-proxy/pull/146)
(v0.22.1), [#133](https://github.com/openshift/kube-rbac-proxy/pull/133) (v0.21.1).

## Contract

| | |
|---|---|
| **Input** | `TAG`: the upstream release tag to merge, e.g. `v0.23.0`. Given by the human. |
| **Output** | Local branch `merge-${TAG}-downstream` with the commits below, plus a report containing a PR title and description. |
| **Never** | Push, open the PR, or comment `/lgtm`, `/approve` or `/verified`: a human does these. Never merge upstream `master`. Never rebase, squash or `git pull` the branch: the next merge finds the last merged tag through its merge commit. |

Resulting commits:

```text
Merge tag 'vX.Y.Z' into merge-vX.Y.Z-downstream
go.mod: align Go version with downstream builder    # only if Step 4 lowers the go line
vendor: bump                                        # only if Step 5 changes vendor/
<fixes to downstream code>                          # only if Step 6 needs them
```

## Background

- Upstream moved from `brancz/kube-rbac-proxy` to `kube-rbac-proxy/kube-rbac-proxy`.
  The Go module path is still `github.com/brancz/kube-rbac-proxy`.
- Downstream builds with an ART-provided Go (`.ci-operator.yaml`,
  `Dockerfile.ocp`), not the Go version upstream uses. RHEL's Go runs with
  `GOTOOLCHAIN=local`, so if `go.mod` requires even one **patch** version more
  than the builder has, every job fails.
- Downstream builds with `GOFLAGS=-mod=vendor`; `vendor/` is committed.
- Downstream carries its own code on top of upstream, and a merge must not drop
  it. The most important piece: `cmd/kube-rbac-proxy/app/kube-rbac-proxy.go`
  puts `hardcodedauthorizer.NewHardCodedMetricsAuthorizer()` (from
  `pkg/hardcodedauthorizer/`) first in the authorizer chain. Its e2e test lives
  in `test/e2e/` and `test/kubetest/`.
- Your shell may forget variables between commands. Step 1 saves them to a
  file, and every later step starts by sourcing it.

## Step 0: Preconditions

```bash
git status --porcelain   # must print nothing

# A fresh clone lacks these remotes; add them.
git remote get-url downstream || git remote add downstream https://github.com/openshift/kube-rbac-proxy.git
git remote get-url upstream   || git remote add upstream https://github.com/kube-rbac-proxy/kube-rbac-proxy.git

git remote get-url downstream   # must end in openshift/kube-rbac-proxy(.git)
git remote get-url upstream     # must end in kube-rbac-proxy/kube-rbac-proxy(.git)

git fetch downstream
git fetch upstream --tags
```

**STOP** if the working tree is not clean, or a remote points to another
repository.

## Step 1: Derive Variables

Do not guess any of these. Derive them:

```bash
TAG=v0.23.0   # from the human

# Last upstream tag merged downstream
PREV_TAG=$(git log -1 --merges --format=%s --grep="Merge tag 'v" downstream/master \
  | sed -E "s/^Merge tag '([^']+)'.*/\1/")

# Upstream releases this merge brings in
COVERS=$(git tag --merged "$TAG" --no-merged "$PREV_TAG" --sort=version:refname | paste -sd' ' -)

# Go minor of the builder images
BUILDER_MINOR=$(git show downstream/master:Dockerfile.ocp | sed -nE '1s/.*golang-([0-9]+\.[0-9]+)-.*/\1/p')
git show downstream/master:.ci-operator.yaml | sed -nE 's/.*golang-([0-9]+\.[0-9]+)-.*/\1/p'   # must equal BUILDER_MINOR

# Go version known to pass downstream CI: a safe lower bound of the builder's version
BUILDER_GO=$(git show downstream/master:go.mod | sed -n 's/^go //p')

UPSTREAM_GO=$(git show "$TAG":go.mod | sed -n 's/^go //p')

cat > "$(git rev-parse --git-dir)/merge.env" <<EOF
TAG=$TAG
PREV_TAG=$PREV_TAG
COVERS="$COVERS"
BUILDER_MINOR=$BUILDER_MINOR
BUILDER_GO=$BUILDER_GO
UPSTREAM_GO=$UPSTREAM_GO
export GOTOOLCHAIN=go$BUILDER_GO
EOF
cat "$(git rev-parse --git-dir)/merge.env"
```

For v0.23.0 this printed:

```text
TAG=v0.23.0
PREV_TAG=v0.22.1
COVERS="v0.23.0"
BUILDER_MINOR=1.26
BUILDER_GO=1.26.3
UPSTREAM_GO=1.27.1
export GOTOOLCHAIN=go1.26.3
```

`GOTOOLCHAIN` pins every `go` command to `BUILDER_GO`, so what passes locally
also passes on the builder.

**Check**:

```bash
source "$(git rev-parse --git-dir)/merge.env"
git merge-base --is-ancestor "$PREV_TAG" "$TAG" && echo ok   # ok
go version                                                    # go version go1.26.3 ...
```

**STOP** if:

- The first check does not print `ok`: `TAG` is missing or not newer than `PREV_TAG`.
- The `.ci-operator.yaml` minor differs from `BUILDER_MINOR`, or `BUILDER_GO`
  does not start with `BUILDER_MINOR`. The builder changed its Go minor; ask
  the human which Go version to use.
- `go version` does not print `go$BUILDER_GO`.

A newer Go in upstream (v0.23.0: 1.27.1, builder: 1.26) is not a STOP. Step 4
lowers the `go` line, and Steps 4–6 show whether the code still builds with
the builder's Go.

## Step 2: Record What Downstream Carries

```bash
source "$(git rev-parse --git-dir)/merge.env"
git diff --stat "$PREV_TAG" downstream/master -- . ':!vendor'
```

Save this output for the report.

**Check**: in `go.mod`, downstream may change only the `go` line.

```bash
git diff "$PREV_TAG" downstream/master -- go.mod | grep -E '^[-+][^-+]' | grep -vE '^[-+]go [0-9.]+$'   # must print nothing
```

**STOP** if it prints anything, e.g. a pinned dependency or a `replace`. Step 3
takes upstream's `go.mod` and would silently drop it.

## Step 3: Create the Branch and Merge

```bash
source "$(git rev-parse --git-dir)/merge.env"
git switch --no-track -c "merge-${TAG}-downstream" downstream/master
git merge --no-ff --no-edit --cleanup=strip --signoff "$TAG"
```

**STOP** if `git switch` fails because the branch already exists.

If `git merge` succeeded, go to the Check. If it reports conflicts, resolve
each conflicted file:

| Conflicted path | Action |
|---|---|
| `go.mod`, `go.sum` | `git checkout --theirs -- <path>` (Step 4 fixes the Go version) |
| Anything else | **STOP**. Report the file, both sides, and a proposed resolution: upstream's code with the downstream change re-applied. Do not commit it. |

Once every conflict is resolved, by the table or by the human, finish the
merge. `--cleanup=strip` drops the `#` lines (tag signature, conflict list)
that git adds to the message.

```bash
git add <resolved files>
git commit --no-edit --cleanup=strip --signoff
```

**Check**:

```bash
git log -1 --format=%s                 # Merge tag 'vX.Y.Z' into merge-vX.Y.Z-downstream
git diff --name-only --diff-filter=U   # must print nothing

# Files downstream carried before the merge but not after it; must print nothing
comm -23 <(git diff --name-only "$PREV_TAG" downstream/master -- . ':!vendor' ':!go.mod' | sort) \
         <(git diff --name-only "$TAG" HEAD -- . ':!vendor' ':!go.mod' | sort)
```

**STOP** if the last command prints a file. Either the merge dropped
downstream code, or downstream carried a cherry-pick that `TAG` now contains;
the human decides.

## Step 4: Align the Go Version

```bash
source "$(git rev-parse --git-dir)/merge.env"
sed -n 's/^go //p' go.mod   # the go line after the merge
```

If it is greater than `BUILDER_GO` (v0.23.0: 1.27.1 > 1.26.3), lower it.
Otherwise skip to Step 5.

```bash
go mod edit -go="$BUILDER_GO" -toolchain=none
go mod tidy
git add go.mod go.sum
git commit -s -m 'go.mod: align Go version with downstream builder'
```

**Check**:

```bash
sed -n 's/^go //p' go.mod   # must be BUILDER_GO or lower
git status --porcelain      # must print nothing
```

**STOP** if `go mod tidy` fails or the `go` line ends up greater than
`BUILDER_GO`. A dependency needs a newer Go than the builder has, so the merge
must wait for ART's builder bump: an openshift-bot PR titled "Updating
kube-rbac-proxy-container image to be consistent with ART", e.g.
[#143](https://github.com/openshift/kube-rbac-proxy/pull/143).

## Step 5: Regenerate vendor/

```bash
source "$(git rev-parse --git-dir)/merge.env"
go mod vendor
git status --porcelain
```

If that printed nothing, skip to the Check. Otherwise commit; the diff is
large, which is expected:

```bash
git add vendor
git commit -s -m 'vendor: bump'
```

**Check**, with the commands `ci/prow/vendor` and `ci/prow/verify-deps` run:

```bash
go mod tidy && go mod vendor && git status --porcelain   # must print nothing
```

## Step 6: Verify

```bash
source "$(git rev-parse --git-dir)/merge.env"
make build
go vet ./...        # also compiles test/e2e, which make test-unit skips
make test-unit
make generate && git diff --exit-code -- . ':!vendor'
git checkout -- vendor   # make generate also rewrites vendored *.md files; drop that
git grep -n 'NewHardCodedMetricsAuthorizer()' -- cmd/
```

**Check**: every command succeeds, and the last one prints a line from
`cmd/kube-rbac-proxy/app/kube-rbac-proxy.go`.

If a failure comes from upstream changing an API that downstream code uses
(downstream code = the files from Step 2):

- Downstream test code (`test/e2e/`, `test/kubetest/`, `*_test.go`): fix the
  downstream code, not upstream's, and commit it separately, e.g.
  `git commit -s -m 'test/e2e: adapt to upstream vX.Y.Z'`.
- Any other downstream code: **STOP** without editing it. Report the error and
  a proposed diff that mirrors how upstream adapted its own code and tests.
  Apply and commit it only after the human approves it.

**STOP** on any other failure. After a fix commit, run Step 6 again.

Past case: in v0.23.0, Kubernetes 1.37 added two methods to
`authorizer.Authorizer`. Upstream implemented them in `pkg/authz/`; the
approved downstream fix did the same in `pkg/hardcodedauthorizer/`.

## Report

When finished, or when stopped, report to the human:

```markdown
Status: DONE | STOPPED at Step N (<reason>)
Branch: merge-vX.Y.Z-downstream (not pushed)
Commits: <git log --oneline --first-parent downstream/master..HEAD>
Covers: <COVERS> (last downstream merge: <PREV_TAG>)
Conflicts: <file → resolution, or "none">
Stops: <every STOP you hit and what the human decided, or "none">
Go: go.mod <go line>, upstream <UPSTREAM_GO>, builder <BUILDER_MINOR>
Downstream carries: <Step 2 file list>, all still present
```

When the status is DONE, also draft the PR:

- **Title**: `<JIRA-KEY>: Merge upstream vX.Y.Z`. Keep the placeholder and ask
  the human for the key; they may answer `NO-JIRA`. Without a prefix the PR
  never gets the `jira/valid-reference` label; an invalid `OCPBUGS-` key adds
  `jira/invalid-bug`. Either one blocks the merge.
- **Body**: write it to a file outside the repository, e.g. `/tmp/pr-body.md`.
  Take the upstream changes only from
  `git diff "$PREV_TAG" "$TAG" -- CHANGELOG.md`:

  ```markdown
  ## Summary

  Merge upstream kube-rbac-proxy <TAG> into OpenShift downstream.
  Covers upstream <COVERS> (last downstream merge was <PREV_TAG>).

  ### Upstream changes

  - <one bullet per CHANGELOG.md entry, shortened; prefix it with its release if COVERS lists several>

  ### Downstream changes

  - <one bullet per resolved conflict and per fix commit>
  - go.mod: go <BUILDER_GO> for the Go <BUILDER_MINOR> ART builder (upstream: <UPSTREAM_GO>)
  - Regenerate vendor/

  ### Known gaps

  - Downstream builds with the Go <BUILDER_MINOR> ART builder, upstream <TAG> with Go <UPSTREAM_GO>. Standard-library fixes reach downstream when ART updates the builder.
  ```

The human pushes the branch to their own fork (not `downstream`, not
`upstream`) and opens the PR:

```bash
git push -u <fork-remote> "merge-${TAG}-downstream"
gh pr create --repo openshift/kube-rbac-proxy --base master \
  --head <github-user>:"merge-${TAG}-downstream" --title "<title>" --body-file /tmp/pr-body.md
```

To merge, the PR needs:

- Passing `ci/prow/images`, `ci/prow/okd-scos-images`, `ci/prow/test-unit`,
  `ci/prow/vendor` and `ci/prow/verify-deps`. `ci/prow/e2e-aws-ovn` starts
  only after `/lgtm`.
- The labels `lgtm` and `approved` (from [OWNERS](OWNERS)),
  `jira/valid-reference`, and `verified`: a human comments `/verified by ci`
  once e2e-aws-ovn passed.

## Troubleshooting

| Symptom | Cause | Action |
|---|---|---|
| `go: go.mod requires go >= X (running go Y; GOTOOLCHAIN=...)` | The `go` line is newer than the builder | Step 4 |
| Step 6 fails with `undefined:` on a standard-library name | Upstream uses a Go API the builder's Go lacks | STOP; wait for ART's builder bump (Step 4) |
| `merge: vX.Y.Z - not something we can merge` | Tags were not fetched | `git fetch upstream --tags` |
| `ci/prow/vendor` or `ci/prow/verify-deps` fails | `vendor/` is out of sync with `go.mod` | Repeat Step 5 |
| PR lacks `jira/valid-reference` | Title has no Jira prefix | Retitle: `<JIRA-KEY>:` or `NO-JIRA:` |
| PR has `jira/invalid-bug` | The `OCPBUGS-` key is not a valid bug | Use a valid key, or `NO-JIRA` |
| PR has `lgtm` and `approved` but does not merge | `verified` is missing | A human comments `/verified by ci` |
| PR has `needs-rebase` | Downstream `master` changed files this PR changes | Do not rebase. Delete the local branch, run this runbook again, and let the human force-push |
