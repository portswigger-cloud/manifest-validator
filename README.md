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
  `kind` and `metadata.name`. Cheap and deterministic, and it reads the tree
  straight from memory.
- `image-policy` — in-process. Image references must be pinned to a digest or a
  tag other than `latest`, and come from an allowed registry. Finds `image:`
  anywhere in a document, including in custom resources this service does not
  model.
- `kics` — runs KICS as a child process, over a tree written to a temporary
  directory, with no shell. The binary, its query library and the report wiring
  are fixed by this image; config chooses the platform types to scan, the
  severities to ignore, and which findings do not fail a verdict.
  `tool_version` is read from the report KICS wrote, so a verdict cannot name a
  version that did not produce it.

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
