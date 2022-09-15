# syntax=docker/dockerfile:1

FROM --platform=linux/amd64 buildpack-deps:buster AS protoc
WORKDIR /protoc

# Install latest protoc binary from https://github.com/protocolbuffers/protobuf/releases
RUN apt-get update \
  && apt-get -f install unzip \
  && rm -rf /var/lib/apt/lists/*
ARG PROTOC_VERSION=21.5
ARG PROTOC_SHASUM=92fb4f5066a6f7b870e09c73115a2c861852af8f6555d8da9955fdb80710bf7f
RUN curl -o /tmp/protoc.zip -L https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip \
  && (echo "${PROTOC_SHASUM} /tmp/protoc.zip" | sha256sum -c) \
  && unzip -o /tmp/protoc.zip -d /protoc bin/protoc \
  && rm /tmp/protoc.zip

###############
FROM node:16.17

WORKDIR /client

COPY --from=protoc /protoc/bin/protoc /usr/local/bin

ARG TSPROTO_VERSION=1.125.0
RUN npm install -g "ts-proto@${TSPROTO_VERSION}"

COPY docker-entrypoint.sh /usr/local/bin
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
