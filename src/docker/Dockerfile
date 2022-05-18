FROM ubuntu:bionic-20220401
RUN dpkg --add-architecture i386
RUN apt update
RUN apt-get -y install gcc
RUN apt-get -y install g++
RUN apt-get -y install make
RUN apt-get -y install wget curl
RUN apt-get -y install git
RUN apt-get -y install openjdk-8-jdk
RUN apt-get -y -oDebug::pkgAcquire::Worker=1 install openjdk-11-jdk 
RUN apt-get install -y mingw-w64
# This package is documented in BUILDING.txt, but doesn't appear to be available.
# RUN apt-get install -y x86_64-w64-mingw32-gcc
RUN apt-get install -y gcc-mingw-w64-i686
RUN apt-get install -y libssl-dev:i386 libssl-dev
RUN apt-get install -y g++-multilib
RUN mkdir -p /usr/local/build
WORKDIR /usr/local/build
RUN wget https://dlcdn.apache.org/maven/maven-3/3.8.5/binaries/apache-maven-3.8.5-bin.tar.gz
RUN tar xzf apache-maven-3.8.5-bin.tar.gz
RUN ln -s ../build/apache-maven-3.8.5/bin/mvn /usr/local/bin
RUN git clone https://gitbox.apache.org/repos/asf/commons-crypto.git commons-crypto
WORKDIR /usr/local/build/commons-crypto
RUN VERSION=1.1.1-SNAPSHOT JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64 make
RUN mvn
CMD bash
