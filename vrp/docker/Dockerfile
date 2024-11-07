FROM public.ecr.aws/docker/library/debian:bookworm-slim
MAINTAINER Kristian Larsson <kristian@spritelink.net>

RUN apt-get update -qy \
    && apt-get upgrade -qy \
    && apt-get install -y \
        qemu-kvm \
        bridge-utils \
        socat \
        iproute2 \
        python3-ipy \
        python3-pexpect \
        ssh \
        git \
        python3-pip \
        && rm -rf /var/lib/apt/lists/*
     
RUN pip install git+https://github.com/carlmontanari/scrapli --break-system-packages

ARG IMAGE
COPY $IMAGE /
COPY *.py /
EXPOSE 22 830 5000 10000-10099

HEALTHCHECK CMD ["/healthcheck.py"]
ENTRYPOINT ["/launch.py"]
