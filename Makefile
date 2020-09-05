PREFIX ?= /usr
DESTDIR ?=

default: build


BINS := hyperctl

.PHONY: hyperctl

$(BINS):
	go build -v -o $@ ./cmd/

build: $(BINS)

install: $(BINS)
	install -s -m 0755 -v $^ $(DESTDIR)$(PREFIX)/bin/$^

.PHONY: container
container:
	docker build -t graytshirt/hyperctl:0.1 .
