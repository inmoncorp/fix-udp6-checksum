FROM alpine:3.23 AS builder
RUN apk update \
 && apk add \
      linux-headers \
      clang \
      libbpf-dev
WORKDIR /build
COPY fix_checksum.c .
RUN clang -O2 -g -target bpf -c fix_checksum.c

FROM scratch AS export
COPY --from=builder /build/fix_checksum.o /

