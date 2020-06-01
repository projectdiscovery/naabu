# Build Container
FROM golang:1.14-alpine AS build-env
RUN apk add --no-cache --upgrade git openssh-client ca-certificates build-base libpcap libpcap-dev
WORKDIR /go/src/app

# Install
RUN go get -u github.com/projectdiscovery/naabu/cmd/naabu

ENTRYPOINT ["naabu"]
