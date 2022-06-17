<!--
  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->

# About

This directory contains scripts needed to build Crypto native code using a Docker image.

The Docker image runs on Ubuntu and includes Maven and cross-compilation tools
which are used to build Linux and Windows native code files (see build.sh for the list).
The image uses virtual mounts for the source code and Maven repository, so the output
of the build is available on the host system and can be included in a subsequent release
build.
# Building with Docker

```
  cd src/docker
  docker compose build crypto
```

# Running with Docker

```
  cd src/docker
  docker compose run crypto # run shell; can then use Maven to do builds
  OR
  docker compose run --entrypoint src/docker/build.sh crypto # run full build
```