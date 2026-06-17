# syntax=docker/dockerfile:1

# SafeCall MCP Server — a stdio MCP server (JSON-RPC over stdin/stdout).
# No network ports are exposed; it is driven by an MCP client over its stdio.

# ---- build stage ----
FROM golang:1.25 AS build
WORKDIR /src

# Cache module downloads independently of source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build a static, stripped binary with the version baked in via ldflags.
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/safecall-mcp-server \
      ./cmd/safecall-mcp-server

# ---- runtime stage ----
# distroless/static: minimal attack surface, no shell, no package manager.
# The :nonroot variant runs the process as UID 65532.
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=build /out/safecall-mcp-server /safecall-mcp-server

USER nonroot:nonroot
ENTRYPOINT ["/safecall-mcp-server"]
