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
package com.intel.chimera.stream;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.security.SecureRandom;
import java.util.Properties;
import java.util.Random;

import com.intel.chimera.cipher.Cipher;
import com.intel.chimera.cipher.CipherTransformation;
import com.intel.chimera.cipher.JceCipher;
import com.intel.chimera.cipher.OpensslCipher;
import com.intel.chimera.utils.ReflectionUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public abstract class AbstractCryptoStreamTest {
  private final int dataLen = 20000;
  private byte[] data = new byte[dataLen];
  private byte[] encData;
  private Properties props;
  private byte[] key = new byte[16];
  private byte[] iv = new byte[16];

  private ByteArrayOutputStream baos = new ByteArrayOutputStream();

  protected static int defaultBufferSize = 8192;
  protected static int smallBufferSize = 1024;

  private final String jceCipherClass = JceCipher.class.getName();
  private final String opensslCipherClass = OpensslCipher.class.getName();
  protected CipherTransformation transformation;

  public abstract void setUp() throws IOException;

  @Before
  public void before() throws IOException {
    Random random = new SecureRandom();
    random.nextBytes(data);
    random.nextBytes(key);
    random.nextBytes(iv);
    props = new Properties();
    setUp();
  }

  /** Test skip. */
  @Test(timeout=120000)
  public void testSkip() throws Exception {
    prepareData();

    doSkipTest(jceCipherClass, false);
    doSkipTest(opensslCipherClass, false);

    doSkipTest(jceCipherClass, true);
    doSkipTest(opensslCipherClass, true);
  }

  /** Test byte buffer read with different buffer size. */
  @Test(timeout=120000)
  public void testByteBufferRead() throws Exception {
    prepareData();

    doByteBufferRead(jceCipherClass, false);
    doByteBufferRead(opensslCipherClass, false);

    doByteBufferRead(jceCipherClass, true);
    doByteBufferRead(opensslCipherClass, true);
  }

  /** Test byte buffer write. */
  @Test(timeout=120000)
  public void testByteBufferWrite() throws Exception {
    doByteBufferWrite(jceCipherClass, false);
    doByteBufferWrite(opensslCipherClass, false);

    doByteBufferWrite(jceCipherClass, true);
    doByteBufferWrite(opensslCipherClass, true);
  }

  private void doSkipTest(String cipherClass, boolean withChannel) throws IOException {
    InputStream in = getCryptoInputStream(cipherClass, defaultBufferSize, withChannel);
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

  private void doByteBufferRead(String cipherClass, boolean withChannel) throws Exception {
    // Default buffer size, initial buffer position is 0
    InputStream in = getCryptoInputStream(cipherClass, defaultBufferSize, withChannel);
    ByteBuffer buf = ByteBuffer.allocate(dataLen + 100);
    byteBufferReadCheck(in, buf, 0);
    in.close();

    // Default buffer size, initial buffer position is not 0
    in = getCryptoInputStream(cipherClass, defaultBufferSize, withChannel);
    buf.clear();
    byteBufferReadCheck(in, buf, 11);
    in.close();

    // Small buffer size, initial buffer position is 0
    in = getCryptoInputStream(cipherClass, smallBufferSize, withChannel);
    buf.clear();
    byteBufferReadCheck(in, buf, 0);
    in.close();

    // Small buffer size, initial buffer position is not 0
    in = getCryptoInputStream(cipherClass, smallBufferSize, withChannel);
    buf.clear();
    byteBufferReadCheck(in, buf, 11);
    in.close();

    // Direct buffer, default buffer size, initial buffer position is 0
    in = getCryptoInputStream(cipherClass, defaultBufferSize, withChannel);
    buf = ByteBuffer.allocateDirect(dataLen + 100);
    byteBufferReadCheck(in, buf, 0);
    in.close();

    // Direct buffer, default buffer size, initial buffer position is not 0
    in = getCryptoInputStream(cipherClass, defaultBufferSize, withChannel);
    buf.clear();
    byteBufferReadCheck(in, buf, 11);
    in.close();

    // Direct buffer, small buffer size, initial buffer position is 0
    in = getCryptoInputStream(cipherClass, smallBufferSize, withChannel);
    buf.clear();
    byteBufferReadCheck(in, buf, 0);
    in.close();

    // Direct buffer, small buffer size, initial buffer position is not 0
    in = getCryptoInputStream(cipherClass, smallBufferSize, withChannel);
    buf.clear();
    byteBufferReadCheck(in, buf, 11);
    in.close();
  }

  private void doByteBufferWrite(String cipherClass, boolean withChannel) throws Exception {
    CryptoOutputStream out = getCryptoOutputStream(cipherClass, defaultBufferSize, withChannel);
    ByteBuffer buf = ByteBuffer.allocateDirect(dataLen / 2);
    buf.put(data, 0, dataLen / 2);
    buf.flip();
    int n1 = out.write(buf);

    buf.clear();
    buf.put(data, n1, dataLen / 3);
    buf.flip();
    int n2 = out.write(buf);

    buf.clear();
    buf.put(data, n1 + n2, dataLen - n1 - n2);
    buf.flip();
    int n3 = out.write(buf);

    Assert.assertEquals(dataLen, n1 + n2 + n3);

    out.flush();
    encData = baos.toByteArray();

    InputStream in = getCryptoInputStream(cipherClass, defaultBufferSize, withChannel);
    buf = ByteBuffer.allocate(dataLen + 100);
    byteBufferReadCheck(in, buf, 0);
    in.close();
  }

  private void byteBufferReadCheck(InputStream in, ByteBuffer buf,
      int bufPos) throws Exception {
    buf.position(bufPos);
    int n = ((ReadableByteChannel) in).read(buf);
    Assert.assertEquals(bufPos + n, buf.position());
    byte[] readData = new byte[n];
    buf.rewind();
    buf.position(bufPos);
    buf.get(readData);
    byte[] expectedData = new byte[n];
    System.arraycopy(data, 0, expectedData, 0, n);
    Assert.assertArrayEquals(readData, expectedData);
  }

  private void prepareData() throws IOException {
    Cipher cipher = null;
    try {
      cipher = (Cipher)ReflectionUtils.newInstance(
          ReflectionUtils.getClassByName(jceCipherClass), props, transformation);
    } catch (ClassNotFoundException cnfe) {
      throw new IOException("Illegal crypto cipher!");
    }

    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    OutputStream out = new CryptoOutputStream(baos, cipher, defaultBufferSize, key, iv);
    out.write(data);
    out.flush();
    encData = baos.toByteArray();
  }

  private CryptoInputStream getCryptoInputStream(String cipherClass, int bufferSize, boolean withChannel)
      throws IOException {
    Cipher cipher = null;
    try {
      cipher = (Cipher)ReflectionUtils.newInstance(
          ReflectionUtils.getClassByName(cipherClass), props, transformation);
    } catch (ClassNotFoundException cnfe) {
      throw new IOException("Illegal crypto cipher!");
    }

    if (withChannel) {
      return new CryptoInputStream(Channels.newChannel(new ByteArrayInputStream(encData)), cipher, bufferSize, key, iv);
    } else {
      return new CryptoInputStream(new ByteArrayInputStream(encData), cipher, bufferSize, key, iv);
    }
  }

  private CryptoOutputStream getCryptoOutputStream(String cipherClass, int bufferSize, boolean withChannel)
      throws IOException {
    Cipher cipher = null;
    try {
      cipher = (Cipher)ReflectionUtils.newInstance(
          ReflectionUtils.getClassByName(cipherClass), props, transformation);
    } catch (ClassNotFoundException cnfe) {
      throw new IOException("Illegal crypto cipher!");
    }

    baos.reset();
    if (withChannel) {
      return new CryptoOutputStream(Channels.newChannel(baos), cipher, bufferSize, key, iv);
    } else {
      return new CryptoOutputStream(baos, cipher, bufferSize, key, iv);
    }
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
