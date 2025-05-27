PROG:=tapir-pop
VERSION:=`cat ./VERSION`
COMMIT:=`git describe --dirty=+WiP --always`
APPDATE=`date +"%Y-%m-%d-%H:%M"`
GOFLAGS:=-v -ldflags "-X app.version=$(VERSION)-$(COMMIT)"

GOOS ?= $(shell uname -s | tr A-Z a-z)

GO:=GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go
# GO:=GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=1 go

SPECFILE:=rpm/SPECS/tapir-pop.spec

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

clean: SHELL:=/bin/bash
clean:
	@rm -f $(PROG) *~ version.go
	@rm -f *.tar.gz
	@rm -f rpm/SOURCES/*.tar.gz
	@rm -rf rpm/{BUILD,BUILDROOT,SRPMS,RPMS}

install:
	mkdir -p /usr/local/libexec
	install -b -c -s ${PROG} /usr/local/libexec/

tarball: version.go
	git archive --format=tar.gz --prefix=$(PROG)/ -o $(PROG)-$(VERSION).tar.gz HEAD

srpm: SHELL:=/bin/bash
srpm: tarball
	test $$(rpmspec -q --qf '%{version}' $(SPECFILE) 2>/dev/null || grep '^Version:' $(SPECFILE) | awk '{print $$2}') == $(VERSION)
	mkdir -p rpm/{BUILD,RPMS,SRPMS}
	cp $(PROG)-$(VERSION).tar.gz rpm/SOURCES/
	rpmbuild -bs --define "%_topdir ./rpm" --undefine=dist $(SPECFILE)
	test -z "$(outdir)" || cp rpm/SRPMS/*.src.rpm "$(outdir)"

.PHONY: build clean generate
