PROG:=tapir-pop
VERSION:=`cat ./VERSION`

COMMIT:=`git describe --dirty=+WiP --always`
APPDATE=`date +"%Y-%m-%d-%H:%M"`
GOFLAGS:=-v -ldflags "-X app.version=$(VERSION)-$(COMMIT) -B gobuildid"

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
	-rm -rf dist/rpm/SPECS/*spec dist/rpm/RPMS dist/rpm/BUILD dist/rpm/SOURCES/$(PROG) dist/rpm/SRPMS dist/rpm/BUILDROOT
	-rm -rf dist/src/
	-rm -rf dist/bin/

install:
	mkdir -p /usr/local/libexec
	install -b -c -s ${PROG} /usr/local/libexec/

srcdist:
	-mkdir -p dist/src
	git archive --format=tar.gz --prefix=$(PROG)/ -o dist/src/$(PROG)-$(VERSION).tar.gz HEAD

bindist: srcdist
	-mkdir -p dist/bin/build
	cp dist/src/$(PROG)-$(VERSION).tar.gz dist/bin/build/
	tar xvf dist/bin/build/$(PROG)-$(VERSION).tar.gz -C dist/bin/build
	rm -f dist/bin/build/*.tar.gz
	cd dist/bin/build/$(PROG) && make build
	mv dist/bin/build/$(PROG)/$(PROG) dist/bin/

rpm: bindist
	-mkdir -p dist/rpm/SPECS dist/rpm/RPMS dist/rpm/BUILD dist/rpm/SOURCES dist/rpm/SRPMS
	cp dist/bin/$(PROG) dist/rpm/SOURCES
	sed -e "s/@@VERSION@@/$(VERSION)/g" dist/rpm/SPECS/$(PROG).spec.in > dist/rpm/SPECS/$(PROG).spec
	cd dist/rpm && rpmbuild --define "_topdir `pwd`" -v -ba SPECS/$(PROG).spec



.PHONY: build clean generate

