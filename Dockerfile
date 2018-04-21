FROM alpine:latest

RUN apk add --no-cache ca-certificates

RUN mkdir /app
COPY https-auto-proxy /app/proxy

RUN chmod +x /app/https-auto-proxy

ENTRYPOINT ["/app/https-auto-proxy"]