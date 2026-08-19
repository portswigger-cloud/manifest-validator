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

FROM gcr.io/distroless/cc-debian13

COPY --from=builder /python /python
COPY --from=builder /deps-venv /venv
COPY --from=builder /venv /venv

# Paths are constants in kics.py; changing them here changes them there.
COPY --from=kics /app/bin/kics /usr/local/bin/kics
COPY --from=kics /app/bin/assets /opt/kics/assets

EXPOSE 8080
USER nonroot
# Explicit so readOnlyRootFilesystem later means mounting a volume here, rather
# than discovering where the scanner chose to write.
ENV TMPDIR=/tmp
ENTRYPOINT ["/venv/bin/manifest-validator"]
