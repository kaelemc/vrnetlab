FROM ghcr.io/srl-labs/vrnetlab-base:0.2.1

ARG VERSION
ENV VERSION=${VERSION}
ARG IMAGE
COPY $IMAGE* /
COPY *.py /

HEALTHCHECK CMD ["/healthcheck.py"]
ENTRYPOINT ["/launch.py"]
