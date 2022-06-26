#!/usr/bin/env bash

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

# Script to build native files under Docker

set -e

cd /home/crypto # must agree with virtual mount in docker-compose.yaml

# Ensure the correct config file is installed
cp /usr/include/x86_64-linux-gnu/openssl/opensslconf.h /usr/include/openssl

# Run the 64-bit builds.
mvn -V package

# use process-classes rather than package to speed up builds
mvn -DskipTests -Drat.skip process-classes -P linux-aarch64
mvn -DskipTests -Drat.skip process-classes -P win64
mvn -DskipTests -Drat.skip process-classes -P linux64

# Ensure the correct config file is installed
cp /usr/include/i386-linux-gnu/openssl/opensslconf.h /usr/include/openssl

# Run the 32-bit builds.
mvn -DskipTests -Drat.skip process-classes -P linux-armhf
mvn -DskipTests -Drat.skip process-classes -P linux-arm
mvn -DskipTests -Drat.skip process-classes -P win32

# see separate script for optional linux32 build

# Show generated files
find target/classes/org/apache/commons/crypto/native -type f -ls
