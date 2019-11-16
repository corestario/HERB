FROM golang:1.12-alpine3.10

RUN apk update
RUN apk upgrade
RUN apk add bash ca-certificates git libc-dev expect make jq
RUN mkdir /root/tmp
ENV GO111MODULE=off
ENV PATH /go/bin:$PATH
ENV GOPATH /go
ENV HERBPATH /go/src/github.com/corestario/HERB
RUN mkdir /go/src/github.com && mkdir /go/src/github.com/corestario && mkdir /go/src/github.com/corestario/HERB
COPY . $HERBPATH
COPY . /root/HERB

WORKDIR $HERBPATH

RUN go install $HERBPATH/cmd/hd
RUN go install $HERBPATH/cmd/hcli
RUN	go install $HERBPATH/cmd/dkgcli

WORKDIR $HERBPATH/scripts

EXPOSE 26656

#RUN ./init_chain.sh 7 12

#RUN sed -i 's/timeout_commit = "5s"/timeout_commit = "1s"/' $HOME/.hd/config/config.toml
