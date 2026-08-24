ARG GO_VERSION=1.27
FROM golang:${GO_VERSION} AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

ARG VERSION=0.0.0-dev
ARG GIT_COMMIT=unknown
ARG BUILD_TIME=unknown

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${GIT_COMMIT} -X main.date=${BUILD_TIME}" \
      -o /usr/local/bin/docker-dns ./cmd/docker-dns

FROM gcr.io/distroless/static-debian13:nonroot

COPY --from=builder /usr/local/bin/docker-dns /usr/local/bin/docker-dns

ENTRYPOINT ["/usr/local/bin/docker-dns"]
