/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.commons.crypto;

import java.util.concurrent.TimeUnit;

import org.apache.commons.crypto.cipher.CryptoCipherFactory;
import org.apache.commons.crypto.random.CryptoRandomFactory;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;

/**
 * Basic Benchmark to compare creation and runtimes for the different implementations.
 * Needs work to improve how well the tests mirror real-world use.
 */
@BenchmarkMode(Mode.AverageTime)
@Fork(value = 1, jvmArgs = "-server")
@Threads(1)
@Warmup(iterations = 10)
@Measurement(iterations = 20)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
public class CryptoBenchmark extends AbstractBenchmark {

    private static final String RANDOM_JAVA        = CryptoRandomFactory.RandomProvider.JAVA.getClassName();
    private static final String RANDOM_OS          = CryptoRandomFactory.RandomProvider.OS.getClassName();
    private static final String RANDOM_OPENSSL     = CryptoRandomFactory.RandomProvider.OPENSSL.getClassName();

    private static final String CIPHER_OPENSSL     = CryptoCipherFactory.CipherProvider.OPENSSL.getClassName();
    private static final String CIPHER_JCE         = CryptoCipherFactory.CipherProvider.JCE.getClassName();

    @Benchmark
    public void RandomCreateOS() throws Exception {
        getRandom(RANDOM_OS);
    }

    @Benchmark
    public void RandomCreateJava() throws Exception {
        getRandom(RANDOM_JAVA);
    }

    @Benchmark
    public void RandomCreateOpenssl() throws Exception {
        getRandom(RANDOM_OPENSSL);
    }

    @Benchmark
    public void RandomTestOS() throws Exception {
        random(RANDOM_OS);
    }

    @Benchmark
    public void RandomTestJava() throws Exception {
        random(RANDOM_JAVA);
    }

    @Benchmark
    public void RandomTestOpenssl() throws Exception {
        random(RANDOM_OPENSSL);
    }

    
    @Benchmark
    public void CipherCreateJce() throws Exception {
        getCipher(CIPHER_JCE);
    }

    @Benchmark
    public void CipherTestJce() throws Exception {
        encipher(CIPHER_JCE);
    }

    @Benchmark
    public void CipherCreateOpenssl() throws Exception {
        getCipher(CIPHER_OPENSSL);
    }

    @Benchmark
    public void CipherTestOpenssl() throws Exception {
        encipher(CIPHER_OPENSSL);
    }

}
