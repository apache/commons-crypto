/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.intel.chimera;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.channels.Channels;
import java.security.SecureRandom;
import java.util.Properties;
import java.util.Random;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.intel.chimera.codec.CryptoCodec;
import com.intel.chimera.codec.OpensslCipher;
import com.intel.chimera.utils.ReflectionUtils;

public class CryptoCodecTest {
  private static final Log LOG= LogFactory.getLog(CryptoCodecTest.class);

  private static final int bufferSize = 4096;

  private byte[] key = new byte[16];
  private byte[] iv = new byte[16];
  private int count = 10000;

  private final String jceCodecClass = 
      "com.intel.chimera.codec.JceAesCtrCryptoCodec";
  private final String opensslCodecClass = 
      "com.intel.chimera.codec.OpensslAesCtrCryptoCodec";

  private Properties props;

  @Before
  public void setUp() throws IOException {
    Random random = new SecureRandom();
    random.nextBytes(key);
    random.nextBytes(iv);
    props = new Properties();
  }

  @Test
  public void testJceAesCtrCryptoCodec() throws Exception {
    Assert.assertEquals(null, OpensslCipher.getLoadingFailureReason());
    cryptoCodecTest(0, jceCodecClass, jceCodecClass, iv);
    cryptoCodecTest(count, jceCodecClass, jceCodecClass, iv);
    cryptoCodecTest(count, jceCodecClass, opensslCodecClass, iv);
    // Overflow test, IV: xx xx xx xx xx xx xx xx ff ff ff ff ff ff ff ff 
    for(int i = 0; i < 8; i++) {
      iv[8 + i] = (byte) 0xff;
    }
    cryptoCodecTest(count, jceCodecClass, jceCodecClass, iv);
    cryptoCodecTest(count, jceCodecClass, opensslCodecClass, iv);
  }

  @Test
  public void testOpensslAesCtrCryptoCodec() throws Exception {
    Assert.assertEquals(null, OpensslCipher.getLoadingFailureReason());
    cryptoCodecTest(0, opensslCodecClass, opensslCodecClass, iv);
    cryptoCodecTest(count, opensslCodecClass, opensslCodecClass, iv);
    cryptoCodecTest(count, opensslCodecClass, jceCodecClass, iv);
    // Overflow test, IV: xx xx xx xx xx xx xx xx ff ff ff ff ff ff ff ff 
    for(int i = 0; i < 8; i++) {
      iv[8 + i] = (byte) 0xff;
    }
    cryptoCodecTest(count, opensslCodecClass, opensslCodecClass, iv);
    cryptoCodecTest(count, opensslCodecClass, jceCodecClass, iv);
  }

  private void cryptoCodecTest(int count, String encCodecClass,
      String decCodecClass, byte[] iv) throws IOException {
    cryptoCodecTestForInputStream(count, encCodecClass, decCodecClass, iv);
    cryptoCodecTestForReadableByteChannel(count, encCodecClass, decCodecClass, iv);
  }

  private void cryptoCodecTestForInputStream(int count, String encCodecClass,
      String decCodecClass, byte[] iv) throws IOException {
    CryptoCodec encCodec = null;
    try {
      encCodec = (CryptoCodec)ReflectionUtils.newInstance(
          ReflectionUtils.getClassByName(encCodecClass), props);
    } catch (ClassNotFoundException cnfe) {
      throw new IOException("Illegal crypto codec!");
    }
    LOG.info("Created a Codec object of type: " + encCodecClass);

    // Generate data
    SecureRandom random = new SecureRandom();
    byte[] originalData = new byte[count];
    byte[] decryptedData = new byte[count];
    random.nextBytes(originalData);
    LOG.info("Generated " + count + " records");

    // Encrypt data
    ByteArrayOutputStream encryptedData = new ByteArrayOutputStream();
    CryptoOutputStream out = new CryptoOutputStream(encryptedData, 
        encCodec, bufferSize, key, iv);
    out.write(originalData, 0, originalData.length);
    out.flush();
    out.close();
    LOG.info("Finished encrypting data");

    CryptoCodec decCodec = null;
    try {
      decCodec = (CryptoCodec)ReflectionUtils.newInstance(
          ReflectionUtils.getClassByName(decCodecClass), props);
    } catch (ClassNotFoundException cnfe) {
      throw new IOException("Illegal crypto codec!");
    }
    LOG.info("Created a Codec object of type: " + decCodecClass);

    // Decrypt data
    CryptoInputStream in = new CryptoInputStream(new ByteArrayInputStream(
        encryptedData.toByteArray()), decCodec, bufferSize, key, iv);

    // Check
    int remainingToRead = count;
    int offset = 0;
    while (remainingToRead > 0) {
      int n = in.read(decryptedData, offset, decryptedData.length - offset);
      if (n >=0) {
        remainingToRead -= n;
        offset += n;
      }
    }

    Assert.assertArrayEquals("originalData and decryptedData not equal",
          originalData, decryptedData);

    // Decrypt data byte-at-a-time
    in = new CryptoInputStream(new ByteArrayInputStream(
        encryptedData.toByteArray()), decCodec, bufferSize, key, iv);

    // Check
    DataInputStream originalIn = new DataInputStream(new BufferedInputStream(new ByteArrayInputStream(originalData)));
    int expected;
    do {
      expected = originalIn.read();
      Assert.assertEquals("Decrypted stream read by byte does not match",
        expected, in.read());
    } while (expected != -1);

    LOG.info("SUCCESS! Completed checking " + count + " records");
  }

  private void cryptoCodecTestForReadableByteChannel(int count, String encCodecClass,
      String decCodecClass, byte[] iv) throws IOException {
    CryptoCodec encCodec = null;
    try {
      encCodec = (CryptoCodec)ReflectionUtils.newInstance(
          ReflectionUtils.getClassByName(encCodecClass), props);
    } catch (ClassNotFoundException cnfe) {
      throw new IOException("Illegal crypto codec!");
    }
    LOG.info("Created a Codec object of type: " + encCodecClass);

    // Generate data
    SecureRandom random = new SecureRandom();
    byte[] originalData = new byte[count];
    byte[] decryptedData = new byte[count];
    random.nextBytes(originalData);
    LOG.info("Generated " + count + " records");

    // Encrypt data
    ByteArrayOutputStream encryptedData = new ByteArrayOutputStream();
    CryptoOutputStream out = new CryptoOutputStream(Channels.newChannel(encryptedData), 
        encCodec, bufferSize, key, iv);
    out.write(originalData, 0, originalData.length);
    out.flush();
    out.close();
    LOG.info("Finished encrypting data");

    CryptoCodec decCodec = null;
    try {
      decCodec = (CryptoCodec)ReflectionUtils.newInstance(
          ReflectionUtils.getClassByName(decCodecClass), props);
    } catch (ClassNotFoundException cnfe) {
      throw new IOException("Illegal crypto codec!");
    }
    LOG.info("Created a Codec object of type: " + decCodecClass);

    // Decrypt data
    CryptoInputStream in = new CryptoInputStream(Channels.newChannel(new ByteArrayInputStream(
        encryptedData.toByteArray())), decCodec, bufferSize, key, iv);

    // Check
    int remainingToRead = count;
    int offset = 0;
    while (remainingToRead > 0) {
      int n = in.read(decryptedData, offset, decryptedData.length - offset);
      if (n >=0) {
        remainingToRead -= n;
        offset += n;
      }
    }

    Assert.assertArrayEquals("originalData and decryptedData not equal",
          originalData, decryptedData);

    // Decrypt data byte-at-a-time
    in = new CryptoInputStream(Channels.newChannel(new ByteArrayInputStream(
        encryptedData.toByteArray())), decCodec, bufferSize, key, iv);

    // Check
    DataInputStream originalIn = new DataInputStream(new BufferedInputStream(new ByteArrayInputStream(originalData)));
    int expected;
    do {
      expected = originalIn.read();
      Assert.assertEquals("Decrypted stream read by byte does not match",
        expected, in.read());
    } while (expected != -1);

    LOG.info("SUCCESS! Completed checking " + count + " records");
  }
}
