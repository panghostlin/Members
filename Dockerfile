FROM golang:1.13.3

WORKDIR /go/src/github.com/panghostlin/Members/

ADD go.mod .
ADD go.sum .
RUN go mod download

ADD . /go/src/github.com/panghostlin/Members

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -o panghostlin-members

RUN chmod +x wait-for-it.sh

ENTRYPOINT [ "/bin/bash", "-c" ]
EXPOSE 8010