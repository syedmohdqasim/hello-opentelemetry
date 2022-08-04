# BUILD STAGE
FROM registry.access.redhat.com/ubi8/go-toolset as builder

USER root

ENV GOPATH=/opt/app-root GOCACHE=/mnt/cache GO111MODULE=on

WORKDIR $GOPATH/src/github.com/golang-ex

COPY . .

RUN go build -o example-app ./opentelemetry-sample-app/hello_opentelemetry.go

# RUN STAGE
FROM registry.access.redhat.com/ubi8/ubi-minimal:8.4

ARG ARCH=amd64

COPY --from=builder /opt/app-root/src/github.com/golang-ex/example-app /usr/bin/example-app
ENTRYPOINT ["/usr/bin/example-app"]
