FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \ 
	apt-get install -y bash apt-utils && \ 
	apt-get install -y git net-tools iputils-ping && \ 
	apt-get install -y host wget tar vim cmake zlib1g-dev && \ 
	apt-get install -y libssl-dev libcmocka-dev g++ libpcre2-dev libxml2-dev

RUN apt-get install -y locate

WORKDIR /root

RUN wget https://git.libssh.org/projects/libssh.git/snapshot/libssh-0.9.2.tar.gz && \ 
	tar -xvf libssh-0.9.2.tar.gz && \ 
	cd libssh-0.9.2 && mkdir build && cd build/ && \ 
	cmake -DUNIT_TESTING=ON -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Debug .. && \ 
	make && make install
RUN git clone --single-branch --branch v2.1.30 https://github.com/CESNET/libyang.git && \ 
	cd libyang/ && mkdir build; cd build && cmake .. && make && make install 

RUN git clone --single-branch --branch v2.2.36 https://github.com/sysrepo/sysrepo.git && \ 
	cd sysrepo/ && mkdir build; cd build && cmake .. && make && make install

RUN git clone --single-branch --branch v2.1.28 https://github.com/CESNET/libnetconf2.git && \ 
	cd libnetconf2/ && mkdir build; cd build && cmake .. && make && make install

RUN ldconfig && updatedb

RUN git clone --single-branch --branch v2.1.49 https://github.com/CESNET/netopeer2.git && \ 
	cd netopeer2/ && mkdir build; cd build && cmake .. && make && make install

RUN rm -rf *

COPY . /root/

CMD ["./setup_netopeer2_server.sh"] 
