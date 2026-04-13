# Build
FROM golang:1.26.2-alpine AS build-env
RUN apk add --no-cache build-base libpcap-dev
WORKDIR /app
COPY . /app
RUN go mod download
RUN CGO_ENABLED=0 go build ./cmd/naabu

# Release
FROM alpine:3.23.3
RUN apk upgrade --no-cache \
    && apk add --no-cache nmap libpcap bind-tools ca-certificates nmap-scripts
COPY --from=build-env /app/naabu /usr/local/bin/
ENTRYPOINT ["naabu"]
