FROM public.ecr.aws/docker/library/debian:bookworm-slim
MAINTAINER Kristian Larsson <kristian@spritelink.net>

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qy \
 && apt-get upgrade -qy \
 && apt-get install -y \
    bridge-utils \
    iproute2 \
    python3-ipy \
    socat \
    qemu-kvm \
    git \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*
 
RUN pip install git+https://github.com/carlmontanari/scrapli --break-system-packages

ARG IMAGE
COPY $IMAGE* /
COPY *.py /

EXPOSE 22 161/udp 830 5000 6000 10000-10099
HEALTHCHECK CMD ["/healthcheck.py"]
ENTRYPOINT ["/launch.py"]
