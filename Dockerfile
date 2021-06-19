FROM golang:1.16.5-alpine AS builder
RUN apk add build-base libpcap-dev
RUN GO111MODULE=on go get -v github.com/projectdiscovery/naabu/v2/cmd/naabu

FROM alpine
RUN apk add nmap libpcap-dev bind-tools ca-certificates
COPY --from=builder /go/bin/naabu /usr/local/bin/naabu
ENTRYPOINT ["naabu"]
