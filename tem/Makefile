PROG:=tem
VERSION:=`cat ./VERSION`
COMMIT:=`git describe --dirty=+WiP --always`
APPDATE=`date +"%Y-%m-%d-%H:%M"`
GOFLAGS:=-v -ldflags "-X app.version=$(VERSION)-$(COMMIT)"

GOOS ?= $(shell uname -s | tr A-Z a-z)
GOARCH:=amd64

GO:=GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go
# GO:=GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=1 go

default: ${PROG}

${PROG}: build

build:	
	/bin/sh make-version.sh $(VERSION)-$(COMMIT) $(APPDATE) $(PROG)
	$(GO) build $(GOFLAGS) -o ${PROG}

clean:
	@rm -f $(PROG)

install:
	mkdir -p /usr/local/libexec
	install -b -c -s ${PROG} /usr/local/libexec/

.PHONY: build clean generate

