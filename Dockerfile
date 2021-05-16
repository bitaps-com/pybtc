FROM ubuntu:18.04
MAINTAINER Aleksey Karpov <admin@bitaps.com>
RUN echo "nameserver 8.8.8.8" > /etc/resolv.comf
RUN apt-get update
# install python

RUN apt-get -y install python3
RUN apt-get -y install python3-pip
RUN apt-get -y install git
RUN apt-get -y install pkg-config libtool autotools-dev automake pkg-config
RUN apt-get -y install build-essential
RUN pip3 install bit
COPY ./ /pybtc
RUN cd pybtc; python3 setup.py install
ENTRYPOINT ["/bin/bash"]