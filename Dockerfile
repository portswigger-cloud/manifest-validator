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

# Straight from Docker Hub, as `github-actions/actions/kics-scan` already does.
# Checkmarx is not a Verified Publisher, so anonymous pulls count against the
# per-IP limit — authenticate the build with DOCKER_TOKEN, the way the existing
# scan workflow does, rather than relying on the allowance.
#
# v2.1.20 is the newest tag Checkmarx publishes an image for; the v2.1.21 GitHub
# release has no image.
FROM checkmarx/kics:v2.1.20 AS kics

FROM gcr.io/distroless/cc-debian13

COPY --from=builder /python /python
COPY --from=builder /deps-venv /venv
COPY --from=builder /venv /venv

# The scanner runs as a child of this process rather than in its own Job, so it
# ships in this image. The query library is most of the size and is what
# `--queries-path` must point at.
COPY --from=kics /app/bin/kics /usr/local/bin/kics
COPY --from=kics /app/bin/assets /opt/kics/assets

EXPOSE 8080
USER nonroot
# A check materialises the tree under TMPDIR. Set explicitly so that adding
# readOnlyRootFilesystem later is a matter of mounting a volume here, rather
# than discovering where the scanner decided to write.
ENV TMPDIR=/tmp
ENTRYPOINT ["/venv/bin/manifest-validator"]
