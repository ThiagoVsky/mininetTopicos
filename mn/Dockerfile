##
# Dockerfile MiniNet Trabalho Final
# autor: Thiago da Silva Moraes
# Universidade de Brasília
# Fevereiro de 2025
##

# Usar a última versão do Ubuntu como base
FROM ubuntu:focal

ARG DEBIAN_FRONTEND=noninteractive

COPY entrypoint.sh /
COPY TopoTopicos.py /

# Atualizar o sistema e instalar dependências necessárias
RUN apt update && apt install -y --no-install-recommends \
    curl \
    telnet \
    dnsutils \
    ifupdown \
    iproute2 \
    iptables \
    iputils-ping \
    mininet \
    net-tools \
    openvswitch-switch \
    tcpdump \
    x11-xserver-utils \
    xterm \
 && rm -rf /var/lib/apt/lists/* \
 && touch /etc/network/interfaces \
 && chmod +x /entrypoint.sh \
 && apt-get clean && rm -rf /var/lib/apt/lists/*
 # && ln /usr/bin/ovs-testcontroller /usr/bin/controller

EXPOSE 6653

ENTRYPOINT ["/entrypoint.sh"]
