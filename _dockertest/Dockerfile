FROM golang:1.26-bookworm
# Pinning apt package versions breaks the build once Debian drops them; the base image tag is the pin.
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev iproute2 ca-certificates python3 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN go build -o /usr/local/bin/naabu ./cmd/naabu
ENTRYPOINT []
