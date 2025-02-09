##
# Dockerfile MiniNet Trabalho Final
# autor: Thiago da Silva Moraes
# Universidade de Brasília
# Fevereiro de 2025
##

#Python 3.8.20 como base
FROM kiemtcb/ryu

COPY entrypoint.sh /
COPY ryu_qos_ips.py /

# Atualizar o sistema e instalar dependências necessárias
RUN pip install --upgrade pip \
    && touch /etc/network/interfaces \
    && chmod +x /entrypoint.sh 

EXPOSE 6653

ENTRYPOINT ["/entrypoint.sh"]