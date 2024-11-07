FROM public.ecr.aws/docker/library/debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qy \
   && apt-get install -y --no-install-recommends \
   bridge-utils \
   iproute2 \
   python3-ipy \
   qemu-kvm \
   qemu-utils \
   socat \
   ssh \
   sshpass \
   git \
   python3-pip \
   && rm -rf /var/lib/apt/lists/*

RUN pip install git+https://github.com/carlmontanari/scrapli --break-system-packages

ARG IMAGE
COPY $IMAGE* /
COPY *.py /
COPY backup.sh /

EXPOSE 22 443 5000 8080
HEALTHCHECK CMD ["/healthcheck.py"]
ENTRYPOINT ["/launch.py"]