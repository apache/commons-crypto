#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#!/bin/bash
set -x
if [ "$#" -ne 2 ];then
  echo "Usage: sh run-benchmark.sh path/to/JDKwithoutAESNIsupport path/to/JDKwithAESNIsupport \n JDK7u45 or higher supports AES-NI."
  exit 1
fi
echo "This benchmark will evaluate the performance of Chimera in different transfomations, ciphers and JDK versions"

if [ ! -f "conf/benchmark.properties" ];then
  echo "Not able to find the benchmark.propety, will use default propety instead"
  cp conf/benchmark.properties.template conf/benchmark.properties
fi

CRYPTO_JAR=`find . -name commons-crypto*.jar`

echo "Using JDK in path $1 to evalue the performance"
$1/bin/java -Djava.library.path="$PATH" -cp $CRYPTO_JAR:target/test-classes org.apache.commons.crypto.benchmark.CommonsCryptoBenchmark conf/benchmark.properties
echo "Using JDK in path $2 to evaluate the performance"
$2/bin/java -Djava.library.path="$PATH" -cp $CRYPTO_JAR:target/test-classes org.apache.commons.crypto.benchmark.CommonsCryptoBenchmark conf/benchmark.properties
