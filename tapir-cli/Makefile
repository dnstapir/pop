PROG:=tapir-cli
# VERSION:=$(shell git describe --dirty=+WiP --always)
VERSION:=`git describe --dirty=+WiP --always`
APPDATE=`date +"%Y-%m-%d-%H:%M"`

GOFLAGS:=-v -ldflags "-X app.version=$(VERSION) -v"

GOOS ?= $(shell uname -s | tr A-Z a-z)
GOARCH:=amd64

GO:=GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go

default: ${PROG}

${PROG}: build

build:
	/bin/sh make-version.sh $(VERSION) ${APPDATE}
	$(GO) build $(GOFLAGS) -o ${PROG}

test:
	$(GO) test -v -cover

clean:
	@rm -f $(PROG) *~ cmd/*~

install:
	install -b -c -s ${PROG} /usr/local/bin/

.PHONY: build clean

