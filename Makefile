
default: build

BINS := hyperctl

.PHONY: hyperctl

hyperctl:
	go build -v -o $@ ./cmd/

build: $(BINS)
