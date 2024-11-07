FROM public.ecr.aws/docker/library/debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qy \
   && apt-get install --no-install-recommends -y \
   iproute2 \
   python3 \
   socat \
   qemu-kvm \
   qemu-utils \
   telnet \
   git \
   python3-pip \
   && rm -rf /var/lib/apt/lists/*

RUN pip install git+https://github.com/carlmontanari/scrapli --break-system-packages

ARG IMAGE
COPY $IMAGE* /
COPY *.py /

EXPOSE 22 80 161/udp 443 830
HEALTHCHECK CMD ["/healthcheck.py"]
ENTRYPOINT ["/launch.py"]
