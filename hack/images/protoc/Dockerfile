# syntax=docker/dockerfile:1
FROM namely/protoc-all@sha256:07f1ba9dbe11f5675e2efc8617c9552217dc4c3eb5ccd108f7c3889878dbae50

COPY docker-entrypoint.sh /usr/local/bin
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
