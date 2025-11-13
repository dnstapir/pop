#######################################
# VERSION SOURCE OF TRUTH FOR PROJECT #
#######################################
VERSION:=0.3.0

PROG:=dnstapir-pop
OUT:=$$(pwd)/out
COMMIT:=$$(cat COMMIT 2> /dev/null || git describe --dirty=+WiP --always 2> /dev/null)
GOFLAGS:=-v -ldflags "-X 'main.version=$(VERSION)' -X 'main.commit=$(COMMIT)' -X 'main.name=$(PROG)'"
GOOS ?= $(shell uname -s | tr A-Z a-z)
GO:=GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go
INSTALL:=install -b -c -s -p -m 0755

# For version snapshots of packages
RPM_VERSION:=$(VERSION)
DEB_VERSION:=$(VERSION)
ifeq ($(VERSION), 0.0.0)
  RPM_VERSION=$(VERSION)^$$(date +%Y%m%d).$(COMMIT)
  DEB_VERSION=$(VERSION)+local$$(date +%Y%m%d).$(COMMIT)
endif

all: default

default: $(PROG)

$(PROG): build

build: outdir
	$(GO) build $(GOFLAGS) -o $(OUT)/$(PROG)

outdir:
	@mkdir -p $(OUT)

install:
	test -z "$(DESTDIR)" && $(INSTALL) $(OUT)/$(PROG) /usr/bin/ || $(INSTALL) $(OUT)/$(PROG) $(DESTDIR)$(prefix)

lint:
	go fmt ./...
	go vet ./...
	staticcheck ./...
	gosec ./...
	golangci-lint run

clean:
	@rm -rf $(OUT)

tarball: outdir
	@echo "$(COMMIT)" > $(OUT)/COMMIT
	@test -z "$$(git status --porcelain)" && git archive --format=tar.gz --prefix=$(PROG)/ -o $(OUT)/$(PROG).tar.gz --add-file $(OUT)/COMMIT HEAD || echo "won't make tarball from dirty history"

srpm: tarball
	cp -r rpm $(OUT)
	sed -e "s/@@VERSION@@/$(RPM_VERSION)/g" $(OUT)/rpm/SPECS/dnstapir-pop.spec.in > $(OUT)/rpm/SPECS/dnstapir-pop.spec
	cp $(OUT)/$(PROG).tar.gz $(OUT)/rpm/SOURCES/
	rpmbuild -bs --define "%_topdir $(OUT)/rpm" --undefine=dist $(OUT)/rpm/SPECS/dnstapir-pop.spec
	cp $(OUT)/rpm/SRPMS/$(PROG)-$(RPM_VERSION)-*.src.rpm $(OUT)
	test -z "$(outdir)" || cp $(OUT)/$(PROG)-$(RPM_VERSION)-*.src.rpm "$(outdir)"

rpm: srpm
	rpmbuild --recompile --define "%_topdir $(OUT)/rpm" --undefine=dist $(OUT)/$(PROG)-$(RPM_VERSION)-*.src.rpm

deb: build
	cp -r deb $(OUT)
	mkdir -p $(OUT)/deb/usr/bin
	mkdir -p $(OUT)/deb/usr/lib/systemd/system
	cp $(OUT)/$(PROG) $(OUT)/deb/usr/bin
	sed -e "s/@@VERSION@@/$(DEB_VERSION)/g" $(OUT)/deb/DEBIAN/control.in > $(OUT)/deb/DEBIAN/control
	dpkg-deb -b $(OUT)/deb/ $(OUT)/$(PROG)-$(DEB_VERSION).deb

.PHONY: build clean generate
