PREFIX ?= /usr
DESTDIR ?=
VERSION ?= $(shell  if [ ! -z $$(git tag --points-at HEAD) ] ; then git tag --points-at HEAD|cat ; else  git rev-parse --short HEAD|cat; fi )
REGISTRY ?= graytshirt
RUNTIME ?= docker
GOOS ?= linux
GOARCH ?= amd64

default: build

BINS := hyperctl

.PHONY: hyperctl

$(BINS):
	CGO_ENABLED=0  go build -v -ldflags "-s -w -X hyperspike.io/hyperctl.Version=${VERSION}" -o $@ ./cmd/

build: $(BINS)

install: $(BINS)
	install -s -m 0755 -v $^ $(DESTDIR)$(PREFIX)/bin/$^

.PHONY: container
container:
	$(RUNTIME) build --build-arg VERSION=$(VERSION) -t $(REGISTRY)/hyperctl:$(VERSION) .

.PHONY: push
push:
	$(RUNTIME) push $(REGISTRY)/hyperctl:$(VERSION)

.PHONY: vet
vet:
	go vet -v ./...

.PHONY: sec
sec:
	@hash gosec > /dev/null 2>&1; if [ $$? -ne 0 ]; then \
		curl https://github.com/securego/gosec/releases/download/v2.4.0/gosec_2.4.0_linux_amd64.tar.gz -OL; \
		tar -xvf gosec*.tar.gz ; \
		cp gosec $(GOPATH)/bin ; \
		rm gosec* ; \
	fi
	gosec ./...

.PHONY: lint
lint:
	@hash golangci-lint > /dev/null 2>&1; if [ $$? -ne 0 ]; then \
		export BINARY="golangci-lint"; \
		curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | sh -s -- -b $(GOPATH)/bin v1.24.0; \
	fi
	golangci-lint run --timeout 5m -v

version:
	@echo "Version: $(VERSION)"

clean:
	rm -f $(BINS)
	go clean -i -r -cache -testcache -modcache -x
