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

FROM gcr.io/distroless/cc-debian13

COPY --from=builder /python /python
COPY --from=builder /deps-venv /venv
COPY --from=builder /venv /venv

EXPOSE 8080
USER nonroot
ENTRYPOINT ["/venv/bin/manifest-validator"]
