FROM golang:1.14
RUN apt update && apt install -y nmap
WORKDIR /go/src/app

# Install
RUN go get -v -u github.com/projectdiscovery/naabu/v2/cmd/naabu

ENTRYPOINT ["naabu"]
