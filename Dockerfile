FROM golang:1.14-alpine3.12 AS builder
RUN apk add build-base libpcap-dev
RUN GO111MODULE=on go get -v github.com/projectdiscovery/naabu/v2/cmd/naabu

FROM alpine:3.12
RUN apk add nmap libpcap-dev
COPY --from=builder /go/bin/naabu /usr/local/bin/naabu
ENTRYPOINT ["naabu"]
