ARG GO_VERSION=1.25
FROM golang:${GO_VERSION} AS builder

WORKDIR /src

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY . .
RUN apt-get update && apt-get install -y --no-install-recommends make && rm -rf /var/lib/apt/lists/*

ARG VERSION=0.0.0-dev
ARG GIT_COMMIT=unknown
ARG BUILD_TIME=unknown
ENV VERSION=$VERSION \
    GIT_COMMIT=$GIT_COMMIT \
    BUILD_TIME=$BUILD_TIME

RUN make build

FROM gcr.io/distroless/static-debian12

COPY --from=builder /src/build/docker-dns /usr/local/bin/docker-dns

ENTRYPOINT ["/usr/local/bin/docker-dns"]
