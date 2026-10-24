# Build bin/capsuled with CGO_ENABLED=0 on the host first; no credentials or CA are baked into this image.
FROM alpine:3.22
RUN addgroup -g 10001 capsule && adduser -D -u 10001 -G capsule capsule
COPY --chown=10001:10001 bin/capsuled /usr/local/bin/capsuled
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/capsuled"]
