/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p/>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p/>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.commons.crypto.benchmark;

import org.apache.commons.crypto.benchmark.option.BenchmarkOption;
import org.apache.commons.crypto.benchmark.option.StreamOption;
import org.apache.commons.crypto.cipher.CipherTransformation;

import java.io.*;
import java.util.Properties;

public class CommonsCryptoBenchmark {
  static String defaultConfigPath = "./conf/benchmark.properties";

  public static void main(String[] args) throws IOException {
    Properties prop = new Properties();
    String propFileName = "benchmark.properties";

    if (args != null && args.length != 0 && args.length != 1 && args.length != 4) {
      System.out.println(
          "Usage: java -Djava.library.path=\"$PATH\" -cp path/to/commons-crypto-[version].jar:path/to/target/test-classes/ org.apache.commons.crypto.benchmark.CommonsCryptoBenchmark [warmupIterations] [iterations] [dataSize] [operationSize] or java -Djava.library.path=\"$PATH\" -cp commons-crypto-[version].jar:path/to/Chimera/target/test-classes/ org.apache.commons.crypto.benchmark.CommonsCryptoBenchmark [path/to/configuration]");
      System.out.println("args[0]: " + args[0]);
      System.exit(1);
    }

    String confFilePath = defaultConfigPath;
    if (args.length == 1) {
      System.out
          .println("Use configurations specified by a configuration file.");
      confFilePath = args[0];
    }

    File configFile = new File(confFilePath);
    InputStream inputStream;

    if (args.length == 0 || args.length == 1) {
      if (configFile.exists()) {
        inputStream = new FileInputStream(configFile);
      } else {
        System.out.println(
            "can not find the configuration file under the current path");
        inputStream = CommonsCryptoBenchmark.class.getClassLoader()
            .getResourceAsStream(propFileName);
      }
      prop.load(inputStream);
    }

    // Benchmark related configurations
    BenchmarkOption.CipherBenchmarkOptionBuilder cipherBenchmarkOptionBuilder
        = BenchmarkOption.newBuilder();
    if(args.length == 1){
      if (prop.containsKey("warmupIterations")) {
        cipherBenchmarkOptionBuilder.buildWarmupIterations(Integer
            .parseInt(prop.getProperty("warmupIterations")));
      }
      if (prop.containsKey("iterations")) {
        cipherBenchmarkOptionBuilder.buildIterations(Integer
            .parseInt(prop.getProperty("iterations")));
      }
      if (prop.containsKey("dataSize")) {
        cipherBenchmarkOptionBuilder.buildDataSize(Integer.parseInt(
            prop.getProperty("dataSize")));
      }
      if (prop.containsKey("operationSize")) {
        cipherBenchmarkOptionBuilder.buildOperationSize(Integer
            .parseInt(prop.getProperty("operationSize")));
      }
    }else{
      // specify by cmd
      cipherBenchmarkOptionBuilder.buildWarmupIterations(Integer
          .parseInt(args[0]));
      cipherBenchmarkOptionBuilder.buildIterations(Integer
          .parseInt(args[1]));
      cipherBenchmarkOptionBuilder.buildDataSize(Integer
          .parseInt(args[2]));
      cipherBenchmarkOptionBuilder.buildOperationSize(Integer
          .parseInt(args[3]));
    }

    BenchmarkOption benchmarkOption = cipherBenchmarkOptionBuilder.create();

    System.out.println("current benchmarkOption option is " + benchmarkOption);
    // Stream related configuration
    String transformations = (prop.contains("transformations")) ? prop
        .getProperty(
            "transformations") : ("AES/CTR/NoPadding,AES/CBC/NoPadding");
    String cipherClazzNames = (prop.contains("cipherClasses")) ? prop
        .getProperty("cipherClasses") : ("org.apache.commons.crypto.cipher" +
        ".OpensslCipher,org.apache.commons.crypto.cipher.JceCipher");
    int bufferSize = (prop.containsKey("bufferSize")) ? Integer
        .parseInt(prop.getProperty("bufferSize")) : (512 * 1024);
    for (String t : transformations.split(",")) {
      for(String c : cipherClazzNames.split(",")){
        CipherTransformation transformation = CipherTransformation.fromName(t);
        StreamOption streamOption = StreamOption.newBuilder()
            .setBufferSize(bufferSize)
            .setCipherTransformation(transformation)
            .setCipherClazzName(c).build();
        System.out.println("current stream option is " + streamOption);
        CryptoStreamBenchmark cryptoStreamBenchmark = new CryptoStreamBenchmark(
            benchmarkOption, streamOption);
        cryptoStreamBenchmark.getBenchMarkData();
      }
    }
  }
}
