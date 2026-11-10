# syntax=docker/dockerfile:1

# Base images are pinned by digest; Dependabot proposes updates.
# The build stage runs natively and cross-compiles, so multi-arch builds
# don't emulate the compiler.
FROM --platform=$BUILDPLATFORM golang:1.27.3-trixie@sha256:af1bfc2614ebb1dbd31af514b78740fd678850e76498762b425ecee4c5c6ea80 AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-trimpath
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
ARG TARGETOS TARGETARCH
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags "-s -w -X main.version=${VERSION}" -o /out/ssshhh-env ./cmd/ssshhh-env
# The server refuses a data directory that group or others can open. A new
# named volume copies this directory's owner and mode.
RUN install -d -m 0700 -o 65532 -g 65532 /out/data

FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
COPY --from=build /out/ssshhh-env /usr/local/bin/ssshhh-env
COPY --from=build --chown=65532:65532 --chmod=0700 /out/data /data
USER 65532:65532
# Relative paths, like the default --data-dir "data", resolve to /data.
WORKDIR /
EXPOSE 2222
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/ssshhh-env"]
CMD ["serve", "--data-dir", "/data"]
