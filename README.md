# manifest-validator

Validates generated Kubernetes manifest trees before they are pushed to a
manifests repository, and returns a verdict that the caller can gate on.

relcoord generates a tree, POSTs it here with a content digest, and pushes only
on a green verdict. This service owns which tools run, the tool versions, the
rulesets and the pass/fail decision; relcoord reads `passed` and knows nothing
else. Callers name checks, they never describe them, so no request can choose a
command to execute.

Companion to the design at `pipeline-design.md`; the as-is pipeline is recorded
at
<https://portswigger.atlassian.net/wiki/spaces/tech/pages/1496350731/Security+Scanning+in+the+Deployment+Pipelines>.

## Shape

```
relcoord ──POST /v1/validate──▶ manifest-validator ──runs──▶ each check in turn
         ◀──── verdict ────────                    (in this process)
```

Every check runs here. In-process checks read the tree from memory; a `command`
check writes it to a temporary directory and runs a tool over it as a child
process. Nothing is scheduled, nothing is pulled, and the service account needs
no Kubernetes permissions at all.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/healthz` | Liveness. |
| `POST` | `/v1/validate` | Validate a tree, return a verdict. |

## Who may call this

Nobody is authenticated. Reachability is a NetworkPolicy question, not an
application one: this service is in-cluster only, it scans content the caller
already controls, and it has no write path to the manifests repository — so a
token bought little and cost a JWT stack, two dependencies and a credential in
every scan pod.

The policy therefore has to exist, and has to say:

- only relcoord may `POST /v1/validate`;
- the namespace defaults to deny, so a missing or mistyped policy fails closed
  rather than silently opening the service to the cluster.

That last point is the one to hold on to. Absent auth in the code, a policy that
does not apply is the whole of the exposure, and nothing here will report it.

### `POST /v1/validate`

The body **is** the tree: a gzipped tar, `Content-Type: application/gzip`.
Everything else travels in the query string, because the body has no room for
it.

```
POST /v1/validate?digest=sha256:…&check=structural&check=image-policy
Content-Type: application/gzip

<gzipped tar of the generated tree>
```

`check` may be repeated and defaults to every check configured with
`default = true`.

The archive is expanded in memory and every member is checked before it is read:
regular files and directories only, no symlinks or devices, no absolute paths, no
`..` in any component, and hard caps on file count and total expanded size — a
small blob must not be able to expand without bound. Any of those is a 400.

Note that the digest is over the *content*, not the blob, so two separately
built archives of the same tree produce the same digest. gzip is not
deterministic, and a verdict keyed on compressed bytes would never hit its
cache.

The response aggregates one verdict per check:

```json
{
  "passed": false,
  "digest": "sha256:…",
  "cached": false,
  "verdicts": [
    {
      "passed": false,
      "tool": "kics",
      "tool_version": "v2.1.16",
      "ruleset_digest": "sha256:…",
      "findings": [
        {"rule_id": "…", "severity": "high", "file": "…", "resource": "…", "message": "…",
         "similarity_id": "…", "accepted": null}
      ]
    }
  ]
}
```

`advisory` says the check reports its findings without failing the verdict, so a
caller showing them to a person can say they blocked nothing.

`accepted` is null when a finding fails the verdict, and otherwise the reason it
does not. `similarity_id` is reported so a one-off suppression can be written
from the verdict rather than by re-running the scanner by hand.

`passed` is decided by the check that produced the findings and is never
recomputed by a caller from the findings list. `tool_version` and
`ruleset_digest` are what make a finding reproducible, and make any
preview-versus-gate disagreement explainable.

Send `Accept: text/event-stream` to stream progress instead. Events are named by
phase, and the last event is `result` or `error`:

```
event: validate          data: {"message": "158 files, checks: structural, kics"}
event: running           data: {"message": "kics: 158 files"}
event: validation-failed data: {"message": "3 findings"}
event: result            data: {…the JSON above…}
```

Phase strings are public API. relcoord forwards them into its own SSE stream,
which is what puts progress into the pull request without any CI change.

## Validating an application's own config

A ConfigMap opts in by carrying annotations manifest-builder wrote for it:

```yaml
metadata:
  annotations:
    manifest-validator.portswigger.com/validate-config: "true"
    manifest-validator.portswigger.com/image: public.ecr.aws/portswigger-platform/idcat:1.0
    manifest-validator.portswigger.com/mount-path: /config
```

The check writes that ConfigMap's data into a directory, runs the named image
with the config mounted read-only where the application expects it, and reads
the exit code. Zero is a valid config; anything else is a `config/invalid`
finding carrying what the image said, truncated.

The image must accept `--validate-config`: check the config, say what is wrong,
exit non-zero, and reach nothing over the network to decide.

The tree names an image and a path, and never a command. The argv is a constant
in this service, so a `system` pull request cannot choose the command line this
pod executes. The image must also match the check's own `allowed-registries`,
which governs what runs *here*, with this service's privileges.

A declaration missing its image or its mount path is a
`config/malformed-declaration` finding rather than a skip: silence would be
indistinguishable from an application with no config to check.

### How the image is run

`crane export` fetches the image's flattened filesystem, and `crun` execs
`--validate-config` in it over a minimal OCI bundle: no network namespace, a
read-only root, a read-only bind mount for the config, every capability dropped,
`noNewPrivileges`, and a non-root uid. Both tools are copied into this image, so
a validation pulls nothing but the image under test.

The isolation is in that bundle, and it is the only isolation there is. Unpacking
an image and exec'ing its entrypoint directly would run a third party's code in
this pod's own namespaces — which a fixed argv and a registry allow-list cannot
protect against. A `crun` that will not start is therefore a `check-error`, not a
fallback to a bare exec.

Two things this needs that the deployment does not have yet: egress to
`public.ecr.aws` so crane can fetch, and somewhere to cache what it fetched so a
repeat validation does not re-pull. Until the first exists the check reports
`check-error` for every declaration, which is why it ships `advisory = true`.

## Content digest

The digest is the key a verdict is about. It lets this service dedupe repeat
scans of identical content, and it self-invalidates: a verdict is valid exactly
as long as the bytes are identical. Digest the content, not the `system` commit —
once manifest-builder resolves image tags at generation time, the same commit
generates different output on different days.

relcoord must compute this identically. Over `sha256`:

1. The literal prefix `manifest-validator-tree-v1\x00`.
2. For each path in ascending byte order of its UTF-8 encoding:
   - the path's byte length as 8 bytes, big-endian;
   - the path's UTF-8 bytes;
   - the content's byte length as 8 bytes, big-endian;
   - the content bytes.

Rendered as `sha256:<hex>`. The lengths are framing, not decoration: without
them `{"ab": "c"}` and `{"a": "bc"}` would hash the same bytes.

A digest mismatch is a 400, not a warning. The server validates what it hashed.

## Checks

Four kinds, all behind one `Checker` seam:

- `structural` — in-process. Every document parses and carries `apiVersion`,
  `kind` and `metadata.name`. Cheap and deterministic, and it reads the tree
  straight from memory.
- `image-policy` — in-process. Image references must be pinned to a digest or a
  tag other than `latest`. Finds `image:` anywhere in a document, including in
  custom resources this service does not model.
- `kics` — runs KICS as a child process, over a tree written to a temporary
  directory, with no shell. The binary, its query library and the report wiring
  are fixed by this image; config chooses the platform types to scan, the
  severities to ignore, and which findings do not fail a verdict.
  `tool_version` is read from the report KICS wrote, so a verdict cannot name a
  version that did not produce it.

- `config` — asks each application whether the config a tree holds for it is
  valid, by running that application's own image over it. Nothing here knows
  what any application's config means, which is the point: only the application
  does. See "Validating an application's own config".

  Which findings fail is a policy, and the policy is expressed here rather than
  in KICS's own `--exclude-*` flags: anything excluded there vanishes from the
  report, so the verdict could not say what it tolerated. Every finding is
  reported; an accepted one carries the reason it does not fail. See
  `[[check.exception]]` in `manifest-validator.toml.example`.

  Exceptions are keyed on **provenance** — the release that produced the file,
  from the `# Source:` header manifest-builder writes — plus a query. Not on a
  count, which cannot distinguish an inherent capability in an upstream chart
  from a false positive in our own code, so raising it for one silently widens
  tolerance for the other. A file with no `# Source:` header (manifest-builder
  synthesises namespaces) can never be accepted by provenance.

  An exception that matches nothing is itself reported, as an accepted
  `kics/unused-exception` finding. That is the signal expiry dates were reaching
  for, without manufacturing failures on a schedule unrelated to whether
  anything changed — and without failing a build because someone fixed the thing
  upstream.

## Advisory checks

`advisory = true` on a `[[check]]` makes it report without failing the verdict.
Every finding is reported and `passed` stays true, so relcoord comments them on
the pull request and deploys anyway.

That is what a check needs while its findings are being worked through. The
alternative is a choice between gating on findings nobody has triaged, which
stops every deployment, and leaving the check out, which means never seeing
them. Neither gets a noisy check into use.

It lives here rather than in relcoord's config for the same reason the rulesets
do: whether a finding stops a deployment is this service's decision. relcoord
gates on `passed` and never recomputes it, so a check can be promoted to gating,
or demoted while a regression is dealt with, by editing this file alone — no
change to the caller and no new image for it.

An advisory check that cannot run does not fail closed, because there is nothing
to fail closed on: nothing is gated on it either way. Its `check-error` finding
is still reported.

A check left advisory indefinitely is one nobody is acting on. Nothing here can
enforce that, which is why the flag reads as a state a check passes through
rather than a mode it lives in.

A check that raises fails closed and reports a `check-error` finding. A `kics`
check whose output cannot be parsed fails rather than passing: a green verdict
that checked nothing is the failure mode worth engineering against.

See `manifest-validator.toml.example` for the full configuration surface. Do not
put rulesets or thresholds in relcoord's config — it is generated by the
pipeline being validated, so a threshold change would need a `system` PR, a
regeneration, an Argo sync and a pod restart.

## Where the scanner comes from

KICS is copied into this image at build time, binary and query library both, so
a validation pulls nothing at all and a cold node costs nothing beyond this
image.

From Docker Hub, as `portswigger-cloud/github-actions/actions/kics-scan`
already does. Checkmarx is not a Verified Publisher, so anonymous pulls count
against the per-IP limit; that workflow passes a `DOCKER_TOKEN` and this build
should too.

The `Dockerfile` pin is the only place the version is stated. A verdict reports
what the report says ran, so the two cannot disagree.

## Development

```bash
uv run pytest                          # full test suite
uv run pytest tests/test_checks.py     # one file
uv run manifest-validator --config-path examples/local.toml

uv run --locked --group dev ruff check
uv run --locked --group dev ruff format --check
uv run --locked --group dev ty check
```

CI runs exactly those four checks. Python >= 3.14; `bktools` comes from the
private index `https://repo.noa.re/`.

## Not done yet

- **ECR publish role:** Crossplane in `system/platform/manifest-validator/extra/`,
  not CDK. Nothing exists in AWS until that PR merges and Argo syncs.
- **Image tag is `REPLACE_ME`.** It passes `image-policy` — the rule rejects
  `latest` and unpinned refs, not placeholders.
- **`ruleset-digest` for the KICS check is a placeholder.** It should be computed
  from the mounted `kics-config` rather than pinned by hand in TOML.
- **KICS contributes nothing for Crossplane resources.** Measured, not assumed:
  scanning 13 real files from `manifests/`, of which 6 are namespaced v2 MRs,
  every finding came back `platform: Kubernetes` and not one of the 18
  `crossplane` queries fired — on v2.1.16 and v2.1.20 alike. The queries
  themselves match on `kind` alone, so the API group is not the problem; KICS
  simply does not classify `aws.m.upbound.io` as Crossplane, and its query
  library contains no reference to `upbound` at all. Those 18 queries also cover
  RDS and DocumentDB rather than the ECR and IAM resources these trees hold, so
  fixing detection would not help much either. The Kubernetes queries are the
  value here — 142 of them, and they found 24 issues in those same files.
- **No blast-radius check.** Nothing here yet catches generation going wrong — an
  empty or truncated tree passes every check above, and Argo prunes what
  disappears. This needs the diff, not just the tree.
- **Trees live in memory.** A restart mid-scan loses the tree and the validation
  fails. S3 is the answer when the exact scanned bytes need retaining against a
  finding.

- **The `config` check has never run against a real image.** Its logic is
  covered by tests with a stubbed runner, and the `crane`/`crun` wiring by tests
  with a stubbed command runner, but nothing here has fetched an image or
  created a namespace. Two things are unverified until it runs in the cluster:
  whether the Dockerfile's `crun` and its libraries actually exec under
  distroless, and whether crun can unshare a user namespace inside this pod's
  `securityContext` at all. The second is the one that decides whether this
  design works.

- **A scanner runs with this service's privileges.** That is only acceptable
  while every tool is offline and unauthenticated, as KICS is. A tool that needs
  egress or a credential — `wizcli` — must not simply be added as another
  `command`; it wants the per-check isolation that Jobs gave, and `git log` has
  that implementation.
- **The NetworkPolicy does not exist.** Until it does there is nothing at all in
  front of this service, and `allow-egress = false` on a check is a label with
  no policy reading it. See "Who may call this".
- **Authentication would have to come back if relcoord moves off-cluster,** or
  if a human or CI job needs to call `/v1/validate` for a preview. Network
  identity does not travel; a token would. It would belong on `/v1/validate`
  only, and `git show` has the deleted implementation.
