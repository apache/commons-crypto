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
# Install dependencies and tooling.
RUN dpkg --add-architecture i386 && apt-get update && apt-get --assume-yes install build-essential \
      && apt-get --assume-yes install openjdk-8-jdk && apt-get --assume-yes install maven \
      && apt-get --assume-yes install libssl-dev:i386 && apt-get --assume-yes install libssl-dev \
      && apt-get --assume-yes install gcc-arm-linux-gnueabi && apt-get --assume-yes install g++-arm-linux-gnueabi \
      && apt-get --assume-yes install gcc-arm-linux-gnueabihf && apt-get --assume-yes install g++-arm-linux-gnueabihf \
      && apt-get --assume-yes install gcc-aarch64-linux-gnu && apt-get --assume-yes install g++-aarch64-linux-gnu \
      && apt-get --assume-yes install mingw-w64 \
# Copy the opensslconf.h file to the base openssl include directory
      && cp /usr/include/x86_64-linux-gnu/openssl/opensslconf.h /usr/include/openssl \
# Create the build directory.
      && mkdir commons-crypto 
COPY . /commons-crypto
# Run the base Linux x86_64 build with tests and then run the cross-compile builds without.
RUN cd commons-crypto && mvn package && mvn -DskipTests package -P linux-arm && mvn -DskipTests package -P linux-armhf \
      && mvn -DskipTests package -P linux-aarch64 && mvn -DskipTests package -P win64