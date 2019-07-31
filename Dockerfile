FROM golang:1.12
ADD . /go/src/github.com/presbrey/nginx-auth-federated
RUN go get -x github.com/presbrey/nginx-auth-federated
CMD ["nginx-auth-federated", "--help"]
