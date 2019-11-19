FROM golang:1.12-alpine3.10

RUN apk add bash # required for automated chain generation

COPY dist/ /usr/local/bin/

CMD ["/usr/local/bin/hd", "start"]
