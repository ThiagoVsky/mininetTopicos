##
# Inicialização Automação Docker
# autor: Thiago da Silva Moraes
# Universidade de Brasília
# Fevereiro de 2025
##

# criar rede no docker e fixar IPs dos containers

# sudo docker run --rm -it --shm-size=512m -p 6901:6901 -e VNC_PW=password kasmweb/core-kali-rolling:1.16.0 #Inicializa o container do Kali Linux


                              #faz o buid do mininet com o dockerfile local

#inicializa o container oficial do Ryu
xterm -e \
		"echo 'Ryu-docker ' && \
		sudo docker run -it --privileged -e DISPLAY=$DISPLAY \
		--network mininet_net \
		--ip 100.100.100.2 \
		-v /tmp/.X11-unix:/tmp/.X11-unix \
		-v /lib/modules:/lib/modules \
		osrg/ryu-book" &

	cd mn/

#inicializa o container do mininer
xterm -e \
		"echo 'mininet' && \
		sudo docker build -t mininet . && \
		sudo docker run -it --rm --privileged -e DISPLAY \
		--network mininet_net \
		--ip 100.100.100.3 \
		-v /tmp/.X11-unix:/tmp/.X11-unix \
		-v /lib/modules:/lib/modules \
		mininet" &
