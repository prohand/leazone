# Independent DNSSEC validator (BIND delv) for the phase 5 test:
#   docker build -t lz-delv -f test/integration/delv.Dockerfile test/integration
FROM mirror.gcr.io/library/alpine:3.22
RUN apk add --no-cache bind-tools && delv -v
