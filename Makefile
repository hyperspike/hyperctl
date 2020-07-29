
default: build

BINS := hyperctl

.PHONY: hyperctl

$(BINS):
	go build -v -o $@ ./cmd/

build: $(BINS)
