##
# Dockerfile MiniNet Trabalho Final
# autor: Thiago da Silva Moraes
# Universidade de Brasília
# Fevereiro de 2025
##

#Python 3.8.20 como base
FROM kiemtcb/ryu

COPY entrypoint.sh /home
COPY ryu_qos_ips.py /home

# Atualizar o sistema e instalar dependências necessárias
# RUN chmod +x ~/entrypoint.sh 

EXPOSE 6653

ENTRYPOINT ["bash"]