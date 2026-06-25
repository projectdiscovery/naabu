FROM golang:1.24-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev iproute2 ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN go build -o /usr/local/bin/naabu ./cmd/naabu
ENTRYPOINT []
