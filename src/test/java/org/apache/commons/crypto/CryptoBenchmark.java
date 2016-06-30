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

import java.nio.ByteBuffer;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.cipher.CryptoCipherFactory;
import org.apache.commons.crypto.conf.ConfigurationKeys;
import org.apache.commons.crypto.random.CryptoRandom;
import org.apache.commons.crypto.random.CryptoRandomFactory;
import org.junit.Assert;
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
public class CryptoBenchmark {

    // TODO replace these with the appropriate public fields/methods when these have been set up
    private static final String RANDOM_OPENSSL_JNA = "org.apache.commons.crypto.jna.OpenSslJnaCryptoRandom";
    private static final String RANDOM_JAVA        = "org.apache.commons.crypto.random.JavaCryptoRandom";
    private static final String RANDOM_OS          = "org.apache.commons.crypto.random.OsCryptoRandom";
    private static final String RANDOM_OPENSSL     = "org.apache.commons.crypto.random.OpenSslCryptoRandom";

    private static final String CIPHER_OPENSSL_JNA = "org.apache.commons.crypto.jna.OpenSslJnaCipher";
    private static final String CIPHER_OPENSSL     = "org.apache.commons.crypto.cipher.OpenSslCipher";
    private static final String CIPHER_JCE         = "org.apache.commons.crypto.cipher.JceCipher";

    private static final byte[] KEY = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
    private static final byte[] IV = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    private static final SecretKeySpec keySpec = new SecretKeySpec(KEY, "AES");
    private static final IvParameterSpec ivSpec = new IvParameterSpec(IV);

    private static final byte[] BUFFER = new byte[1000];

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
    public void RandomTestOpensslJNA() throws Exception {
        random(RANDOM_OPENSSL_JNA);
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
    public void RandomCreateOpensslJNA() throws Exception {
        getRandom(RANDOM_OPENSSL_JNA);
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

    @Benchmark
    public void CipherCreateOpensslJna() throws Exception {
        getCipher(CIPHER_OPENSSL_JNA);
    }

    @Benchmark
    public void CipherTestOpensslJna() throws Exception {
        encipher(CIPHER_OPENSSL_JNA);
    }

    private void random(String cipherClass) throws Exception {
        CryptoRandom random = getRandom(cipherClass);
        random.nextBytes(new byte[1000]);
        random.nextBytes(new byte[1000]);
        random.close();
    }

    private void encipher(String cipherClass) throws Exception {
        CryptoCipher enCipher = getCipher(cipherClass);
        enCipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        final int bufferSize = 1024;
        ByteBuffer inBuffer = ByteBuffer.allocateDirect(bufferSize);
        ByteBuffer outBuffer = ByteBuffer.allocateDirect(bufferSize);
        inBuffer.put(BUFFER);
        inBuffer.flip();
        enCipher.doFinal(inBuffer, outBuffer);
        enCipher.close();
    }

    private CryptoRandom getRandom(String className) throws Exception {
        Properties props = new Properties();
        props.setProperty(ConfigurationKeys.SECURE_RANDOM_CLASSES_KEY, className);
        final CryptoRandom cryptoRandom = CryptoRandomFactory.getCryptoRandom(props);
        Assert.assertEquals(className, cryptoRandom.getClass().getCanonicalName());
        return cryptoRandom;
    }

    private CryptoCipher getCipher(String className) throws Exception {
        Properties properties = new Properties();
        properties.setProperty(ConfigurationKeys.CIPHER_CLASSES_KEY, className);
        CryptoCipher cipher = CryptoCipherFactory.getCryptoCipher("AES/CBC/PKCS5Padding", properties);
        Assert.assertEquals(className, cipher.getClass().getCanonicalName());
        return cipher;
    }

}
