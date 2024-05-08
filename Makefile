PROG:=tem
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

build: version.go
	$(GO) build $(GOFLAGS) -o ${PROG}

linux:	
	/bin/sh make-version.sh $(VERSION)-$(COMMIT) $(APPDATE) $(PROG)
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -o ${PROG}.linux

gen-mqtt-msg-new-qname.go: checkout/events-mqtt-message-new_qname.json
	go-jsonschema checkout/events-mqtt-message-new_qname.json --package main --tags json --only-models --output gen-mqtt-msg-new-qname.go

gen-mqtt-msg.go: checkout/events-mqtt-message.json
	go-jsonschema checkout/events-mqtt-message.json --package main --tags json --only-models --output gen-mqtt-msg.go

checkout/events-mqtt-message-new_qname.json: checkout
	cd checkout; python schemasplit.py events-mqtt-message-new_qname.yaml

checkout/events-mqtt-message.json: checkout
	cd checkout; python schemasplit.py events-mqtt-message.yaml

checkout:
	git clone git@github.com:dnstapir/protocols.git checkout

clean:
	@rm -f $(PROG) *~ version.go

install:
	mkdir -p /usr/local/libexec
	install -b -c -s ${PROG} /usr/local/libexec/

.PHONY: build clean generate

