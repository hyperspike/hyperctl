FROM golang:1.15.7-alpine3.12 AS build

COPY ./ $GOPATH/src/hyperspike/hyperctl

ARG VERSION

RUN apk --no-cache add make binutils \
	&& cd $GOPATH/src/hyperspike/hyperctl \
	&& make VERSION=${VERSION} PREFIX=/usr install


FROM alpine:3.12.3

COPY --from=build /usr/bin/hyperctl /usr/bin/hyperctl

RUN apk --no-cache add bash bash-completion ca-certificates \
	&& addgroup -S hyperspike && adduser -S hyperspike -G hyperspike \
	&& echo -e "source /etc/profile\nsource <(hyperctl completion bash)" > /home/hyperspike/.bashrc

USER hyperspike

CMD /bin/bash
