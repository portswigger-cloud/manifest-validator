# manifest-validator

Validates generated Kubernetes manifest trees before they are pushed to a
manifests repository, and returns a verdict that the caller can gate on.

relcoord generates a tree, POSTs it here with a content digest, and pushes only
on a green verdict. This service owns Job creation, the tool versions, the
rulesets and the pass/fail decision; relcoord reads `passed` and knows nothing
else. Callers name checks, they never describe them, so no request can choose an
image to execute.

Companion to the design at `pipeline-design.md`; the as-is pipeline is recorded
at
<https://portswigger.atlassian.net/wiki/spaces/tech/pages/1496350731/Security+Scanning+in+the+Deployment+Pipelines>.

## Shape

```
relcoord ──POST /v1/validate──▶ manifest-validator ──creates──▶ Job (one per check)
         ◀──── verdict ────────                    ◀─GET /v1/trees/{digest}─┘
```

Nothing is pushed into a Job and no volume is shared: an init container fetches
the tree over HTTP and unpacks it into `/tree`, authenticating with the Job's own
projected service-account token. Each check therefore reaches the tree endpoint
as itself.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/healthz` | Unauthenticated liveness. |
| `POST` | `/v1/validate` | Validate a tree, return a verdict. |
| `GET` | `/v1/trees/{digest}` | Serve an in-flight tree as an uncompressed tar. |

`/v1/trees` requires the same `[[role]]` authentication as `/v1/validate`: the
tree contains the trust configuration, so it must be no easier to reach than the
endpoint that produced it.

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
        {"rule_id": "…", "severity": "high", "file": "…", "resource": "…", "message": "…"}
      ]
    }
  ]
}
```

`passed` is decided by the check that produced the findings and is never
recomputed by a caller from the findings list. `tool_version` and
`ruleset_digest` are what make a finding reproducible, and make any
preview-versus-gate disagreement explainable.

Send `Accept: text/event-stream` to stream progress instead. Events are named by
phase, and the last event is `result` or `error`:

```
event: validate          data: {"message": "158 files, checks: structural, kics"}
event: scheduling        data: {"message": "kics: creating Job"}
event: running           data: {"message": "kics: pod Running"}
event: validation-failed data: {"message": "3 findings"}
event: result            data: {…the JSON above…}
```

Phase strings are public API. relcoord forwards them into its own SSE stream,
which is what puts progress into the pull request without any CI change.

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

Three kinds, all behind one `Checker` seam:

- `structural` — in-process. Every document parses and carries `apiVersion`,
  `kind` and `metadata.name`. Cheap and deterministic; there is no reason to
  schedule a pod for it.
- `image-policy` — in-process. Image references must be pinned to a digest or a
  tag other than `latest`, and come from an allowed registry. Finds `image:`
  anywhere in a document, including in custom resources this service does not
  model.
- `job` — runs a tool in its own Job, with its own privileges. `allow-egress`
  and `service-account` are per check, which is why KICS (no egress, no
  credential) and `wizcli` (both) are separate Jobs rather than one fat scanner.

A check that raises fails closed and reports a `check-error` finding. A `kics`
check whose output cannot be parsed fails rather than passing: a green verdict
that checked nothing is the failure mode worth engineering against.

See `manifest-validator.toml.example` for the full configuration surface. Do not
put rulesets or thresholds in relcoord's config — it is generated by the
pipeline being validated, so a threshold change would need a `system` PR, a
regeneration, an Argo sync and a pod restart.

## Where check images come from

Every Job image is pulled by the kubelet on whichever node the Job lands on, so
the registry and the node cache both matter.

**Not `docker.io`.** `portswigger-cloud/docker-sync` treats Docker Hub as a last
resort, and Checkmarx carries no Verified Publisher badge, so its pulls count
against the anonymous per-IP limit. Every node in these clusters leaves through a
single NAT instance, so the whole cluster shares one bucket — and a rate-limited
pull on a fail-closed gate stops pushes. KICS is not on the ECR public gallery
and `ghcr.io/checkmarx/kics` is not public, so the mirror in `docker-sync` is the
documented answer. Note it syncs the 20 most recent tags on a daily cron: pin to
a tag it actually carries.

**`imagePullPolicy: IfNotPresent`,** explicitly, on both containers. This is the
default for a tagged image, but the cost of getting it wrong is a full re-pull on
every validation, which is most of the latency budget.

Cache warmth is not guaranteed, and this is worth knowing before optimising for
it: the Karpenter default NodePool consolidates empty or underutilized nodes
after `10m` and expires every node after `72h`. A validation that runs less often
than that lands on a cold node and pulls again. At 72 MB compressed for KICS,
from a registry in the same region, that is a few seconds rather than the thing
to engineer around — but it is why the timeout budget assumes a pull, and why a
much larger scanner image would need a genuine cache (a DaemonSet that pre-pulls,
or an ECR pull-through cache) rather than luck.

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

- **The ECR publish role does not exist.** `.github/workflows/publish-image.yml`
  assumes `product-roles/manifest-validator-ecr-publish` in account
  `436027055282`, which needs creating in CDK with a trust policy for this
  repository. Until then the image cannot be published.
- **`ruleset-digest` for the KICS check is a placeholder.** It should be computed
  from the mounted `kics-config` rather than pinned by hand in TOML.
- **KICS and Crossplane v2 is unverified.** The managed resources in these trees
  are namespaced v2 MRs (`iam.aws.m.upbound.io`); KICS's Crossplane queries were
  written against `*.aws.upbound.io`. If they match on `apiVersion` they will
  silently miss all of them. Run KICS over `manifests/` and count findings by
  query before relying on the check.
- **No blast-radius check.** Nothing here yet catches generation going wrong — an
  empty or truncated tree passes every check above, and Argo prunes what
  disappears. This needs the diff, not just the tree.
- **Trees live in memory.** A restart mid-scan loses the tree and the Job pulling
  it fails. S3 is the answer when the exact scanned bytes need retaining against
  a finding.
- **`auth.py` duplicates relcoord's `[[role]]` validation.** The TOML shape is
  deliberately identical; the code should become a shared package on the private
  index rather than two implementations drifting.
