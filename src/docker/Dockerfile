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

# This file creates a Docker image for use in building various native binaries
# for Linux 64-bit and 32-bit, and Windows 64-bit and 32-bit.
# See the README for further details.

FROM ubuntu:18.04

ENV JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64
ENV MAVEN_HOME=/opt/maven
ENV PATH=${MAVEN_HOME}/bin:${PATH}
# Install 64-bit dependencies and tooling.
RUN apt-get update && apt-get --assume-yes install software-properties-common \
      && add-apt-repository ppa:openjdk-r/ppa && apt-get update \
      && apt-get --assume-yes install openjdk-8-jdk \
      && apt-get --assume-yes install build-essential \
      && apt-get --assume-yes install libssl-dev \
      && apt-get --assume-yes install gcc-aarch64-linux-gnu \
      && apt-get --assume-yes install g++-aarch64-linux-gnu \
      && apt-get --assume-yes install mingw-w64 \
      && apt-get --assume-yes install wget \
# Bug workaround see https://github.com/docker-library/openjdk/issues/19.
      && /var/lib/dpkg/info/ca-certificates-java.postinst configure

# Install 32-bit dependencies and tooling.
RUN dpkg --add-architecture i386 && apt-get update \
      && apt-get --assume-yes install libssl-dev:i386 \
      && apt-get --assume-yes install gcc-arm-linux-gnueabi \
      && apt-get --assume-yes install g++-arm-linux-gnueabi \
      && apt-get --assume-yes install gcc-arm-linux-gnueabihf \
      && apt-get --assume-yes install g++-arm-linux-gnueabihf

# Do this separately to make upgrades easier
RUN wget https://dlcdn.apache.org/maven/maven-3/3.6.3/binaries/apache-maven-3.6.3-bin.tar.gz \
&& tar xf apache-maven-*.tar.gz -C /opt && ln -s /opt/apache-maven-3.6.3 /opt/maven

# Ensure we are in the correct directory (this will be overlaid by the virtual mount)
WORKDIR /home/crypto

CMD /bin/bash
