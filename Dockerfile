# Override BASE_IMAGE to build from another registry, e.g. docker.io/library/golang:1.27
ARG BASE_IMAGE=golang:1.27
# Builds on the build platform and cross-compiles, so a multi-arch build needs no emulation.
FROM --platform=$BUILDPLATFORM ${BASE_IMAGE} AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath -o exporter ./cmd/kubescape-findings-exporter

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /workspace/exporter /exporter
USER 65532:65532
ENTRYPOINT ["/exporter"]
