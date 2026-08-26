FROM astral/uv:trixie-slim AS builder

WORKDIR /build

COPY pyproject.toml uv.lock README.md ./
ENV VIRTUAL_ENV=/deps-venv
ENV UV_PYTHON_INSTALL_DIR=/python
RUN uv venv /deps-venv && uv sync --frozen --no-install-project --no-dev --active

COPY src ./src/

RUN uv build --wheel
ENV VIRTUAL_ENV=/venv
RUN uv venv /venv && uv pip install --no-deps dist/*.whl

# Checkmarx is not a Verified Publisher, so anonymous pulls count against the
# per-IP limit; authenticate with DOCKER_TOKEN as the kics-scan action does.
# v2.1.20 is the newest tag with an image — the v2.1.21 release has none.
FROM checkmarx/kics:v2.1.20 AS kics

# The two halves of "run a container": crane fetches an image's filesystem from
# the registry, crun execs a process in it. No daemon, and nothing pulled at
# validation time beyond the image under test.
FROM gcr.io/go-containerregistry/crane:v0.20.6 AS crane

# Debian's crun rather than a release tarball: apt gives a signed, distro-pinned
# binary without a checksum to keep up to date by hand. Its shared libraries come
# with it — discovered here rather than listed, so a new dependency in a later
# version does not silently produce an image that cannot exec.
FROM debian:trixie-slim AS crun
RUN apt-get update \
 && apt-get install -y --no-install-recommends crun \
 && mkdir -p /out \
 && cp /usr/bin/crun /out/crun \
 && ldd /usr/bin/crun | awk '{print $3}' | grep '^/' \
    | xargs -I {} cp --parents {} /out/

FROM gcr.io/distroless/cc-debian13

COPY --from=builder /python /python
COPY --from=builder /deps-venv /venv
COPY --from=builder /venv /venv

# Paths are constants in kics.py; changing them here changes them there.
COPY --from=kics /app/bin/kics /usr/local/bin/kics
COPY --from=kics /app/bin/assets /opt/kics/assets

# Names are constants in containers.py; changing them here changes them there.
COPY --from=crane /ko-app/crane /usr/local/bin/crane
COPY --from=crun /out/crun /usr/local/bin/crun
COPY --from=crun /out/usr /usr

EXPOSE 8080
USER nonroot
# Explicit so readOnlyRootFilesystem later means mounting a volume here, rather
# than discovering where the scanner chose to write.
ENV TMPDIR=/tmp
ENTRYPOINT ["/venv/bin/manifest-validator"]
