# BUILDER
FROM golang:1.14 AS builder
WORKDIR /app
COPY . .
RUN apt update && apt install -y libpcap-dev
RUN go get -d -v ./...
RUN go build -o naabu ./v2/cmd/naabu/

# RUNNER
FROM debian:buster
RUN mkdir /app
WORKDIR /app
RUN apt update && apt install -y nmap libpcap-dev
COPY --from=builder /app/naabu /app/naabu
COPY --from=builder /app/scripts /app/scripts

ENTRYPOINT ["/app/naabu"]
