FROM golang:1.17.0-alpine AS builder
RUN apk add build-base libpcap-dev
RUN GO111MODULE=on go get -v github.com/projectdiscovery/naabu/v2/cmd/naabu

FROM alpine:3.14
RUN apk add nmap libpcap-dev bind-tools ca-certificates
COPY --from=builder /go/bin/naabu /usr/local/bin/naabu
ENTRYPOINT ["naabu"]
