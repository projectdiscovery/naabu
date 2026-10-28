FROM alpine:latest

LABEL org.opencontainers.image.authors="ProjectDiscovery"
LABEL org.opencontainers.image.description="Naabu is a port scanning tool written in Go that allows you to enumerate valid ports for hosts in a fast and reliable manner."
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.title="naabu"
LABEL org.opencontainers.image.url="https://github.com/projectdiscovery/naabu"

RUN apk upgrade --no-cache \
    && apk add --no-cache nmap libpcap bind-tools ca-certificates nmap-scripts

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/naabu /usr/local/bin/

ENTRYPOINT ["naabu"]
