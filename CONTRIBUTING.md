# Contributing

This service is built for one pipeline: relcoord generates a Kubernetes
manifest tree, this validates it, and a green verdict is what allows the push.
The configuration encodes PortSwigger's policy and the caller is internal, so
the repository is published to be read and forked rather than adopted.

That shapes what we can take. Bug reports, and fixes for anything that is wrong
on its own terms — the tar reader, the digest, a check that misreads its tool's
output — are welcome. A change that generalises the service, adds a
configuration knob for a pipeline other than ours, or moves policy out of this
repository is likely to be declined, however good it is; please open an issue
before writing it.

## Working on it

```bash
uv run pytest
uv run --locked --group dev ruff check
uv run --locked --group dev ruff format --check
uv run --locked --group dev ty check
```

CI runs exactly those four, and nothing here needs credentials — every
dependency is on PyPI. Please keep it that way.

`CLAUDE.md` is the architecture guide: what each module is for, and which
decisions are deliberate rather than accidental. Read it before changing a
seam.

## Conventions

- Every source and test file starts with the two SPDX header lines and
  `from __future__ import annotations`.
- A check that cannot interpret its tool's output must fail. A green verdict
  that checked nothing is the failure this service exists to prevent, so a
  change that can produce one will not be merged.
- Document user-visible endpoint or config changes in `README.md` and
  `manifest-validator.toml.example`.
- Commit messages explain why; the diff already says what.

By contributing you agree your work is licensed under the MIT licence in
`LICENSE`.
