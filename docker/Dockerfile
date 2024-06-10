FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \ 
	apt-get install -y bash apt-utils && \ 
	apt-get install -y git net-tools

#CMD ["bash"]
WORKDIR /root
CMD ["sleep", "infinity"]
