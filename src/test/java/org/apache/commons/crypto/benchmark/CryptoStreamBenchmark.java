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
import org.apache.commons.crypto.conf.ConfigurationKeys;
import org.apache.commons.crypto.stream.CryptoInputStream;
import org.apache.commons.crypto.stream.CryptoOutputStream;

import java.io.*;
import java.util.Calendar;
import java.util.Properties;
import java.util.Random;
import java.util.TimeZone;

public class CryptoStreamBenchmark {
  protected String benchMarkName;
  protected BenchmarkOption benchmarkOption;
  protected StreamOption streamOption;
  byte[] inputData;
  CryptoInputStream cryptoInputStream;
  OutputStream cryptoOutputStream;
  ByteArrayInputStream inputStream;
  ByteArrayOutputStream outputStream;

  public CryptoStreamBenchmark(BenchmarkOption benchmarkOption,
      StreamOption streamOption) {
    this.benchmarkOption = benchmarkOption;
    this.streamOption = streamOption;
    outputStream = new ByteArrayOutputStream(benchmarkOption.dataSize);
    inputData = prepareData(benchmarkOption.dataSize);
    inputStream = new ByteArrayInputStream(inputData);
    benchMarkName = "Benchmark test using " + streamOption
        .getCipherClazzName() + " in transformation " + streamOption
        .getTransformation();
  }

  OutputStream getCryptoOutputStream() throws IOException {
    if (cryptoOutputStream == null) {
      Random r = new Random();
      byte[] iv = new byte[16];
      byte[] key = new byte[16];
      r.nextBytes(iv);
      r.nextBytes(key);

      Properties props = new Properties();
      props.put(ConfigurationKeys.CHIMERA_CRYPTO_CIPHER_CLASSES_KEY,
          streamOption.getCipherClazzName());
      props.put(ConfigurationKeys.CHIMERA_CRYPTO_STREAM_BUFFER_SIZE_KEY,
          streamOption.getBufferSize());
      cryptoOutputStream = new CryptoOutputStream(
          streamOption.getTransformation(), props, outputStream, key, iv);
    }
    return cryptoOutputStream;
  }

  protected InputStream getCryptoInputStream() throws IOException {
    if (cryptoInputStream == null) {
      Random r = new Random();
      byte[] iv = new byte[16];
      byte[] key = new byte[16];
      r.nextBytes(iv);
      r.nextBytes(key);

      Properties props = new Properties();
      props.put(ConfigurationKeys.CHIMERA_CRYPTO_CIPHER_CLASSES_KEY,
          streamOption.getCipherClazzName());
      props.put(ConfigurationKeys.CHIMERA_CRYPTO_STREAM_BUFFER_SIZE_KEY,
          streamOption.getBufferSize());
      cryptoInputStream = new CryptoInputStream(
          streamOption.getTransformation(), props, inputStream, key, iv);
    }
    return cryptoInputStream;
  }

  protected byte[] prepareData(int size) {
    byte[] data = new byte[size];
    Random r = new Random();
    r.nextBytes(data);
    return data;
  }

  public void testEncryption(int iterations) {
    try {
      OutputStream cryptoOutputStream = getCryptoOutputStream();

      System.out.println("warming up");
      // warm up
      for (int i = 0; i < benchmarkOption.warmupIterations; i++) {
        doWriteOperation(outputStream, cryptoOutputStream, inputData);
      }

      System.out.println("warming up complete.");

      long begin = Calendar.getInstance(TimeZone.getTimeZone("UTC"))
          .getTimeInMillis();
      for (int i = 0; i < iterations; i++) {
        doWriteOperation(outputStream, cryptoOutputStream, inputData);
      }

      long end = Calendar.getInstance(TimeZone.getTimeZone("UTC"))
          .getTimeInMillis();
      printResult("===encryption",
          1000.0 * benchmarkOption.dataSize * iterations / ((end - begin) *
              1024.0 * 1024.0));
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  public void testDecryption(int iterations) {
    try {
      InputStream cryptoInputStream = getCryptoInputStream();

      byte[] outputData = new byte[benchmarkOption.dataSize];

      System.out.println("Warming up.");
      // warm up
      for (int i = 0; i < benchmarkOption.warmupIterations; i++) {
        doReadOperation(inputStream, cryptoInputStream, outputData);
      }

      System.out.println("warming up complete.");
      long begin = Calendar.getInstance(TimeZone.getTimeZone("UTC"))
          .getTimeInMillis();

      for (int i = 0; i < iterations; i++) {
        doReadOperation(inputStream, cryptoInputStream, outputData);
      }

      long end = Calendar.getInstance(TimeZone.getTimeZone("UTC"))
          .getTimeInMillis();
      printResult("=== decryption",
          1000.0 * benchmarkOption.dataSize * iterations / ((end - begin) *
              1024.0 * 1024.0));
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  private void doWriteOperation(ByteArrayOutputStream outputStream,
      OutputStream cryptoOutputStream, byte[] inputData)
      throws IOException {
    int offset = 0;
    int remaining = benchmarkOption.dataSize;
    while (remaining > 0) {
      int len = (benchmarkOption.operationSize < remaining) ?
          benchmarkOption.operationSize : remaining;
      cryptoOutputStream.write(inputData, offset, len);
      offset += len;
      remaining -= len;
    }
    outputStream.reset();
  }

  private void doReadOperation(ByteArrayInputStream inputStream,
      InputStream cryptoInputStream, byte[] outputData)
      throws IOException {
    int remaining = benchmarkOption.dataSize;
    int offset = 0;
    while (remaining > 0) {
      int len = (remaining < benchmarkOption.operationSize) ? remaining :
          benchmarkOption.operationSize;
      int v = cryptoInputStream.read(outputData, offset, len);
      offset += v;
      remaining -= v;
    }
    inputStream.reset();
  }

  public void getBenchMarkData() {
    System.out.println();
    System.out.println(getBenchMarkName() + " begins!");
    System.out.println("Encryption starts.");
    testEncryption(benchmarkOption.iterations);
    System.out.println("Encryption ends.");

    System.out.println("Decryption starts.");
    testDecryption(benchmarkOption.iterations);
    System.out.println("Decryption ends.");
    System.out.println(getBenchMarkName() + " ends!");
    System.out.println();
  }

  protected String getBenchMarkName() {
    return benchMarkName;
  }

  protected void printResult(String operation, double timeCost) {
    System.out.println(
        "result of " + getBenchMarkName() + " for the " + operation + " operation is " + timeCost +
            " M/s");
    System.out.println();
  }
}
