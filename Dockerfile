FROM golang:1.15.1-alpine3.12 AS build

COPY ./ $GOPATH/src/hyperspike/hyperctl

RUN apk --no-cache add make binutils \
	&& cd $GOPATH/src/hyperspike/hyperctl \
	&& make install


FROM alpine:3.12.0

COPY --from=build /usr/bin/hyperctl /usr/bin/hyperctl

RUN apk --no-cache add bash bash-completion \
	&& echo -e "source /etc/profile\nsource <(hyperctl completion bash)" > ${HOME}/.bashrc

CMD /bin/bash
