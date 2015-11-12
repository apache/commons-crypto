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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.Channels;
import java.security.SecureRandom;
import java.util.Properties;
import java.util.Random;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.intel.chimera.codec.CryptoCodec;
import com.intel.chimera.utils.ReflectionUtils;

public class CryptoStreamTest {
  private final int dataLen = 10000;
  private byte[] data = new byte[dataLen];
  private byte[] encData;
  private final int bufferSize = 4096;
  private Properties props;
  private byte[] key = new byte[16];
  private byte[] iv = new byte[16];

  private final String jceCodecClass = 
      "com.intel.chimera.codec.JceAesCtrCryptoCodec";
  private final String opensslCodecClass = 
      "com.intel.chimera.codec.OpensslAesCtrCryptoCodec";

  @Before
  public void setUp() throws IOException {
    Random random = new SecureRandom();
    random.nextBytes(data);
    random.nextBytes(key);
    random.nextBytes(iv);
    props = new Properties();
  }

  /** Test skip. */
  @Test
  public void testSkip() throws Exception {
    prepareData();

    doSkipTest(getCryptoInputStream(jceCodecClass));
    doSkipTest(getCryptoInputStream(opensslCodecClass));

    doSkipTest(getCryptoInputStreamForChannel(jceCodecClass));
    doSkipTest(getCryptoInputStreamForChannel(opensslCodecClass));
  }

  private void doSkipTest(InputStream in) throws IOException {
    byte[] result = new byte[dataLen];
    int n1 = readAll(in, result, 0, dataLen / 3);

    long skipped = in.skip(dataLen / 3);
    int n2 = readAll(in, result, 0, dataLen);

    Assert.assertEquals(dataLen, n1 + skipped + n2);
    byte[] readData = new byte[n2];
    System.arraycopy(result, 0, readData, 0, n2);
    byte[] expectedData = new byte[n2];
    System.arraycopy(data, dataLen - n2, expectedData, 0, n2);
    Assert.assertArrayEquals(readData, expectedData);

    try {
      skipped = in.skip(-3);
      Assert.fail("Skip Negative length should fail.");
    } catch (IllegalArgumentException e) {
      Assert.assertTrue(e.getMessage().contains("Negative skip length"));
    }

    // Skip after EOF
    skipped = in.skip(3);
    Assert.assertEquals(skipped, 0);

    in.close();
  }

  private void prepareData() throws IOException {
    CryptoCodec codec = null;
    try {
      codec = (CryptoCodec)ReflectionUtils.newInstance(
          ReflectionUtils.getClassByName(jceCodecClass), props);
    } catch (ClassNotFoundException cnfe) {
      throw new IOException("Illegal crypto codec!");
    }

    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    OutputStream out = new CryptoOutputStream(baos, codec, bufferSize, key, iv);
    out.write(data);
    out.flush();
    encData = baos.toByteArray();
  }

  private InputStream getCryptoInputStream(String codecClass) throws IOException {
    CryptoCodec codec = null;
    try {
      codec = (CryptoCodec)ReflectionUtils.newInstance(
          ReflectionUtils.getClassByName(codecClass), props);
    } catch (ClassNotFoundException cnfe) {
      throw new IOException("Illegal crypto codec!");
    }

    return new CryptoInputStream(new ByteArrayInputStream(encData), codec, bufferSize, key, iv);
  }

  private InputStream getCryptoInputStreamForChannel(String codecClass) throws IOException {
    CryptoCodec codec = null;
    try {
      codec = (CryptoCodec)ReflectionUtils.newInstance(
          ReflectionUtils.getClassByName(codecClass), props);
    } catch (ClassNotFoundException cnfe) {
      throw new IOException("Illegal crypto codec!");
    }

    return new CryptoInputStream(Channels.newChannel(new ByteArrayInputStream(encData)), codec, bufferSize, key, iv);
  }

  private int readAll(InputStream in, byte[] b, int off, int len) 
      throws IOException {
    int n = 0;
    int total = 0;
    while (n != -1) {
      total += n;
      if (total >= len) {
        break;
      }
      n = in.read(b, off + total, len - total);
    }
    
    return total;
  }
}
