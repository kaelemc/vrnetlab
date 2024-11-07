FROM public.ecr.aws/docker/library/debian:bookworm-slim

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qy \
   && apt-get upgrade -qy \
   && apt-get install -y \
   bridge-utils \
   iproute2 \
   python3-ipy \
   socat \
   qemu-kvm \
   tcpdump \
   tftpd-hpa \
   ssh \
   inetutils-ping \
   dnsutils \
   openvswitch-switch \
   iptables \
   nftables \
   telnet \
   git \
   python3-pip \
   && rm -rf /var/lib/apt/lists/*

RUN pip install git+https://github.com/carlmontanari/scrapli --break-system-packages

ARG IMAGE
COPY $IMAGE* /
COPY *.py /

EXPOSE 22 23 161/udp 443 830 5000 10000-10099
HEALTHCHECK CMD ["/healthcheck.py"]
ENTRYPOINT ["/launch.py"]
