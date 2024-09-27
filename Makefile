PROG:=tapir-pop
VERSION:=`cat ./VERSION`
COMMIT:=`git describe --dirty=+WiP --always`
APPDATE=`date +"%Y-%m-%d-%H:%M"`
GOFLAGS:=-v -ldflags "-X app.version=$(VERSION)-$(COMMIT)"

GOOS ?= $(shell uname -s | tr A-Z a-z)

GO:=GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go
# GO:=GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=1 go

default: ${PROG}

${PROG}: build

version.go:
	/bin/sh make-version.sh $(VERSION)-$(COMMIT) $(APPDATE) $(PROG)

build: version.go # ../tapir/tapir.pb.go
	$(GO) build $(GOFLAGS) -o ${PROG}

lint:
	go fmt ./...
	go vet ./...
	staticcheck ./...
	gosec ./...
	golangci-lint run

linux:	
	/bin/sh make-version.sh $(VERSION)-$(COMMIT) $(APPDATE) $(PROG)
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -o ${PROG}.linux

netbsd:	
	/bin/sh make-version.sh $(VERSION)-$(COMMIT) $(APPDATE) $(PROG)
	GOOS=netbsd GOARCH=amd64 go build $(GOFLAGS) -o ${PROG}.netbsd

clean:
	@rm -f $(PROG) *~ version.go

install:
	mkdir -p /usr/local/libexec
	install -b -c -s ${PROG} /usr/local/libexec/

.PHONY: build clean generate

