FROM ubuntu:18.04
MAINTAINER Aleksey Karpov <admin@bitaps.com>
RUN apt-get update
# install python

RUN apt-get -y install python3
RUN apt-get -y install python3-pip
RUN apt-get -y install git
RUN apt-get -y install build-essential libtool autotools-dev automake pkg-config libssl-dev libevent-dev

RUN pip3 install git+https://github.com/bitaps-com/aiojsonrpc
RUN pip3 install colorlog
RUN pip3 install aiohttp
RUN pip3 install pyzmq
RUN pip3 install uvloop
RUN pip3 install pybtc

COPY ./ /
WORKDIR /

ENTRYPOINT ["/bin/bash"]