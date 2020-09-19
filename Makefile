PREFIX ?= /usr
DESTDIR ?=
VERSION ?= $(shell  if [ ! -z $$(git tag --points-at HEAD) ] ; then git tag --points-at HEAD|cat ; else  git rev-parse --short HEAD|cat; fi )
REGISTRY ?= graytshirt
RUNTIME ?= docker

default: build

BINS := hyperctl

.PHONY: hyperctl

$(BINS):
	go build -v -ldflags "-X hyperspike.io/hyperctl.Version=${VERSION}" -o $@ ./cmd/

build: $(BINS)

install: $(BINS)
	install -s -m 0755 -v $^ $(DESTDIR)$(PREFIX)/bin/$^

.PHONY: container
container:
	$(RUNTIME) build --build-arg VERSION=$(VERSION) -t $(REGISTRY)/hyperctl:$(VERSION) .

.PHONY: push
push:
	$(RUNTIME) push $(REGISTRY)/hyperctl:$(VERSION)

version:
	@echo "Version: $(VERSION)"
