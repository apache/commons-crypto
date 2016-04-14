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
package org.apache.commons.crypto.benchmark.option;

public class BenchmarkOption {
  public int dataSize;
  public int operationSize;
  public int warmupIterations;
  public int iterations;

  private BenchmarkOption() {
  }

  private BenchmarkOption(int dataSize, int operationSize,
      int warmupIterations, int iterations) {
    this.dataSize = dataSize;
    this.operationSize = operationSize;
    this.warmupIterations = warmupIterations;
    this.iterations = iterations;
  }

  public static CipherBenchmarkOptionBuilder newBuilder() {
    return new CipherBenchmarkOptionBuilder();
  }

  public String toString() {
    return "dataSize is " + dataSize + " operationSize is " + operationSize +
        " warmupIterations is " + warmupIterations + " iterations is " +
        iterations;
  }

  public static class CipherBenchmarkOptionBuilder {
    public static final int DEFAULT_DATASIZE = 1073741824;
    public static final int DEFAULT_OPERATIONSIZE = 8192;
    public static final int DEFAULT_WARMUPITERATIONS = 1000;
    public static final int DEFAULT_ITERATIONS = 1000;
    public int dataSize = DEFAULT_DATASIZE;
    public int operationSize = DEFAULT_OPERATIONSIZE;
    public int warmupIterations = DEFAULT_WARMUPITERATIONS;
    public int iterations = DEFAULT_ITERATIONS;

    public CipherBenchmarkOptionBuilder buildDataSize(int dataSize) {
      this.dataSize = dataSize;
      return this;
    }

    public CipherBenchmarkOptionBuilder buildOperationSize(int operationSize) {
      this.operationSize = operationSize;
      return this;
    }

    public CipherBenchmarkOptionBuilder buildWarmupIterations(
        int warmupIterations) {
      this.warmupIterations = warmupIterations;
      return this;
    }

    public CipherBenchmarkOptionBuilder buildIterations(int iterations) {
      this.iterations = iterations;
      return this;
    }

    public BenchmarkOption create() {
      return new BenchmarkOption(dataSize, operationSize, warmupIterations,
          iterations);
    }
  }
}
