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

# Run some additional tests

crypto() {
  CLASS=$1
  echo crypto $CLASS
  # This adds the necessary libraries
  mvn -q exec:java -Dexec.mainClass=org.apache.commons.crypto.$CLASS
  echo ""
}

example() {
  CLASS=$1
  echo example $CLASS
  mvn -q exec:java  -Dexec.classpathScope=test -Dexec.mainClass=org.apache.commons.crypto.examples.$CLASS
  echo ""
}

java -cp target/classes  org.apache.commons.crypto.Crypto

example CipherByteArrayExample

example RandomExample

example StreamExample

crypto jna.OpenSslJna
