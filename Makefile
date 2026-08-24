#######################################
# VERSION SOURCE OF TRUTH FOR PROJECT #
#######################################
VERSION:=0.0.0

PROG:=dnstapir-pop
OUT:=$$(pwd)/out
COMMIT:=$$(cat COMMIT 2> /dev/null || git describe --dirty=+WiP --always 2> /dev/null)
# Test builds deliberately do NOT reuse $(GO), for two reasons.
#
# It sets CGO_ENABLED=0 for reproducible static release builds, and the race
# detector requires cgo -- with it off, "go test -race" fails outright rather
# than quietly running unraced.
#
# And GOOS/GOARCH are cleared EXPLICITLY, not merely left unset: a test binary
# built for another platform cannot be run by the machine that built it, and
# the go command reads GOOS/GOARCH from the environment. Simply not passing
# them through is not enough -- "GOOS=linux make test" would still cross-compile
# and then fail to run. An empty value is treated as unset by the go command,
# so this pins the tests to the host whatever the caller's environment says.
GOTEST:=GOOS= GOARCH= CGO_ENABLED=1 go

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

# The unit suite, with the race detector ALWAYS on. Wired into CI as the
# merge gate.
#
# -race is not a separate opt-in target on purpose. This repository's
# high-priority backlog is dominated by one bug class -- data races on the
# served RPZ zone (#149, #150, #151, #153, #157) -- which is exactly the class
# the detector finds mechanically. A suite that was run without it answers a
# question nobody is asking.
#
# Kept deliberately to the fast in-process suite. The integration rig (#185)
# belongs in its own target and its own CI job: it will want containers and
# wall-clock that a per-PR gate must not have, and "make test" staying quick is
# what stops it being switched off the first time it is inconvenient.
test:
	$(GOTEST) test -race -cover ./...

# Same suite plus a coverage profile on disk, for looking at rather than gating.
test-coverage: outdir
	$(GOTEST) test -race -coverprofile=$(OUT)/coverage.out ./...
	$(GOTEST) tool cover -func=$(OUT)/coverage.out | tail -1
	@echo "HTML: go tool cover -html=$(OUT)/coverage.out"

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
	rpmbuild --rebuild --define "%_topdir $(OUT)/rpm" --undefine=dist $(OUT)/$(PROG)-$(RPM_VERSION)-*.src.rpm
	cp $(OUT)/rpm/RPMS/*/$(PROG)-$(RPM_VERSION)-*.rpm $(OUT)
	test -z "$(outdir)" || cp $(OUT)/$(PROG)-$(RPM_VERSION)-*.rpm "$(outdir)"

deb: build
	cp -r deb $(OUT)
	mkdir -p $(OUT)/deb/usr/bin
	mkdir -p $(OUT)/deb/usr/lib/systemd/system
	cp $(OUT)/$(PROG) $(OUT)/deb/usr/bin
	sed -e "s/@@VERSION@@/$(DEB_VERSION)/g" $(OUT)/deb/DEBIAN/control.in > $(OUT)/deb/DEBIAN/control
	dpkg-deb -b $(OUT)/deb/ $(OUT)/$(PROG)-$(DEB_VERSION).deb

.PHONY: build clean generate test test-coverage
