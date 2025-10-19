#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License. See accompanying LICENSE file.

# script to build native libraries
# requires Docker and macOS

set -ex

mvn clean

# build linux 64 bit libraries
docker compose -f src/docker/docker-compose.yaml run --quiet-pull crypto src/docker/build-x86_64

# build linux 32 bit libraries
docker compose -f src/docker/docker-compose.yaml run crypto src/docker/build_linux32.sh

# Speed up builds by disabling unnecessary plugins
# Note: spdx.skip requires version 0.7.1+
MAVEN_ARGS="-V -B -ntp -Drat.skip -Djacoco.skip -DbuildNumber.skip -Danimal.sniffer.skip -Dcyclonedx.skip -Dspdx.skip"
# requires Maven 3.9.0+ to be automatically read

# build 64 bit macOS libraries
mvn process-classes -Dtarget.name=mac64 ${MAVEN_ARGS}
mvn process-classes -Dtarget.name=macArm64 ${MAVEN_ARGS}
mvn process-classes -Dtarget.name=mac-aarch64 ${MAVEN_ARGS}

# package it all up
mvn package -DskipTests ${MAVEN_ARGS}
