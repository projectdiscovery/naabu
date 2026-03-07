# Go parameters
GOCMD=go
GOBUILD=CGO_ENABLED=0 $(GOCMD) build
GOMOD=$(GOCMD) mod
GOTEST=$(GOCMD) test
GOFLAGS := -v 
LDFLAGS := -s -w

all: build
build:
	$(GOBUILD) $(GOFLAGS) -ldflags '$(LDFLAGS)' -o "naabu" cmd/naabu/main.go
test: 
	$(GOTEST) $(GOFLAGS) ./...
tidy:
	$(GOMOD) tidy
