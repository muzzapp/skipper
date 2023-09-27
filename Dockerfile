FROM public.ecr.aws/docker/library/golang:1.21.0-bookworm as builder

RUN mkdir /app
WORKDIR /app

COPY go.mod go.sum /app/

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go mod tidy \
    && go mod download

COPY . /app

# Note: CGO_ENABLED=1 is required for the teapot plugin to build

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=1 \
    go \
    build \
    -trimpath \
    -o bin/skipper \
    main.go

FROM scratch

COPY --from=builder /etc/ssl/certs /etc/ssl/certs

# Discovered by running `ldd bin/skipper` and `ldd plugins/filters/teapot/teapot.so` on the builder image
COPY --from=builder /lib/aarch64-linux-gnu/libc.so.6 /lib/aarch64-linux-gnu/libc.so.6
COPY --from=builder /lib/ld-linux-aarch64.so.1 /lib/ld-linux-aarch64.so.1

COPY --from=builder /app/bin/skipper /bin/skipper
COPY --from=builder /app/routes.eskip /routes.eskip

ENTRYPOINT ["/bin/skipper"]