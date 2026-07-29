FROM golang:1.25-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev iproute2 ca-certificates python3 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN go build -o /usr/local/bin/naabu ./cmd/naabu
ENTRYPOINT []
