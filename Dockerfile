# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This file builds the Linux-x86_64, Linux-arm, Linux-armfh. Linux aarch64 and Win64 jnilibs.  It copies the contents of
# the build host's project directory (commons-crypto) into the docker image and cross compiles the remaining builds. If 
# you run this script from a Mac after a successful build, the build in the resuing Docker image will include the Mac 
# build.

FROM ubuntu:18.04
ENV JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
RUN dpkg --add-architecture i386 && apt-get update && apt-get --assume-yes install build-essential \
      && apt-get --assume-yes install openjdk-8-jdk && apt-get --assume-yes install maven \
      && apt-get --assume-yes install libssl-dev:i386 && apt-get --assume-yes install libssl-dev \
      && apt-get --assume-yes install gcc-arm-linux-gnueabi && apt-get --assume-yes install g++-arm-linux-gnueabi \
      && apt-get --assume-yes install gcc-arm-linux-gnueabihf && apt-get --assume-yes install g++-arm-linux-gnueabihf \
      && apt-get --assume-yes install gcc-aarch64-linux-gnu && apt-get --assume-yes install g++-aarch64-linux-gnu \
      && apt-get --assume-yes install mingw-w64 && apt-get --assume-yes install wget && apt-get --assume-yes install curl
RUN mkdir commons-crypto 
COPY . /commons-crypto
RUN cd commons-crypto && mvn package
# Build openssl from source to generate the platform-specific opensslconf.h for the cross-compilers
RUN wget https://www.openssl.org/source/openssl-1.1.1.tar.gz && tar -xvzf openssl-1.1.1.tar.gz && cd openssl-1.1.1 \
      && ./Configure mingw64 shared --cross-compile-prefix=x86_64-w64-mingw32- && make 
RUN cd commons-crypto && mvn -DskipTests package -P win64
RUN cd openssl-1.1.1 && make clean && ./Configure linux-armv4 shared --cross-compile-prefix=arm-linux-gnueabi- && make 
RUN cd commons-crypto && mvn -DskipTests package -P linux-arm && mvn -DskipTests package -P linux-armhf
RUN cd openssl-1.1.1 && make clean && ./Configure linux-aarch64 shared --cross-compile-prefix=aarch64-linux-gnu- && make 
RUN cd commons-crypto && mvn -DskipTests package -P linux-aarch64