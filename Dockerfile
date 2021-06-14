FROM golang:1.16.5-alpine3.13 AS build

ARG VERSION

WORKDIR $GOPATH/src/hyperspike/hyperctl

COPY ./ $GOPATH/src/hyperspike/hyperctl/

# hadolint ignore=DL3018
RUN apk --no-cache add make binutils \
	&& make VERSION=${VERSION} PREFIX=/usr install

FROM alpine:3.13

COPY --from=build /usr/bin/hyperctl /usr/bin/hyperctl

# hadolint ignore=DL3018
RUN apk --no-cache add bash bash-completion ca-certificates \
	&& addgroup -S hyperspike && adduser -S hyperspike -G hyperspike \
	&& printf "source /etc/profile\nsource <(hyperctl completion bash)\n" > /home/hyperspike/.bashrc

USER hyperspike

CMD ["/bin/bash"]
