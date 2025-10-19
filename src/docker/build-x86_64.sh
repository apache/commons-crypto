#!/usr/bin/env bash

# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Script to build native files under Docker

set -ex

cd /home/crypto # must agree with virtual mount in docker-compose.yaml

# Ensure the correct config file is installed
cp /usr/include/x86_64-linux-gnu/openssl/opensslconf.h /usr/include/openssl

# Speed up builds by disabling unnecessary plugins
# Note: spdx.skip requires version 0.7.1+
MAVEN_ARGS="-V -B -ntp -Drat.skip -Djacoco.skip -DbuildNumber.skip -Danimal.sniffer.skip -Dcyclonedx.skip -Dspdx.skip"
# requires Maven 3.9.0+ to be automatically read

# Run the 64-bit builds (no test)
mvn clean test -DskipTests ${MAVEN_ARGS}

# use process-classes rather than package to speed up builds
mvn process-classes -Dtarget.name=linux-aarch64 ${MAVEN_ARGS}
mvn process-classes -Dtarget.name=linux-riscv64 ${MAVEN_ARGS}
mvn process-classes -Dtarget.name=win64 ${MAVEN_ARGS}
mvn process-classes -Dtarget.name=linux64 ${MAVEN_ARGS}

# Ensure the correct config file is installed
cp /usr/include/i386-linux-gnu/openssl/opensslconf.h /usr/include/openssl

# Run the 32-bit builds.
mvn process-classes -Dtarget.name=linux-armhf ${MAVEN_ARGS}
mvn process-classes -Dtarget.name=linux-arm ${MAVEN_ARGS}
mvn process-classes -Dtarget.name=win32 ${MAVEN_ARGS}

# see separate script for optional linux32 build

# Show generated files
find target/classes/org/apache/commons/crypto/native -type f -ls
