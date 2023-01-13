FROM golang:1.18.4-alpine3.15 AS builder
WORKDIR /go/src/github.com/wzshiming/fake-kubelet
COPY . .
ENV CGO_ENABLED=0
RUN go install ./cmd/fake-kubelet

FROM alpine/openssl
COPY --from=builder /go/bin/fake-kubelet /usr/local/bin/
ADD gencrt.sh .
ADD certs/kubelet-ca.crt certs/kubelet-ca.crt
ADD certs/kubelet-ca.key certs/kubelet-ca.key

ENTRYPOINT ["sh", "-c", "mkdir -p pki; sh gencrt.sh; /usr/local/bin/fake-kubelet"]
