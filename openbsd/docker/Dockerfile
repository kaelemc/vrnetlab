FROM public.ecr.aws/docker/library/debian:bookworm-slim

ARG DEBIAN_FRONTEND=noninteractive
ARG DISK_SIZE=4G

RUN apt-get update -qy \
   && apt-get upgrade -qy \
   && apt-get install -y \
   bridge-utils \
   iproute2 \
   python3-ipy \
   socat \
   qemu-kvm \
   tcpdump \
   ssh \
   inetutils-ping \
   dnsutils \
   iptables \
   nftables \
   telnet \
   cloud-utils \
   sshpass \
   git \
   python3-pip \
   && rm -rf /var/lib/apt/lists/*

RUN pip install git+https://github.com/carlmontanari/scrapli --break-system-packages

ARG IMAGE
COPY $IMAGE* /
COPY *.py /
COPY --chmod=0755 backup.sh /

RUN qemu-img resize /${IMAGE} ${DISK_SIZE}

EXPOSE 22 5000 10000-10099
HEALTHCHECK CMD ["/healthcheck.py"]
ENTRYPOINT ["/launch.py"]
