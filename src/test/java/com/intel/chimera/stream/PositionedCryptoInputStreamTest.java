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

import com.intel.chimera.cipher.Cipher;
import com.intel.chimera.cipher.CipherTransformation;
import com.intel.chimera.cipher.JceCipher;
import com.intel.chimera.cipher.OpensslCipher;
import com.intel.chimera.stream.input.Input;
import com.intel.chimera.utils.ReflectionUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Properties;
import java.util.Random;

public class PositionedCryptoInputStreamTest {

  private final int dataLen = 20000;
  private byte[] testData = new byte[dataLen];
  private byte[] encData;
  private Properties props = new Properties();
  private byte[] key = new byte[16];
  private byte[] iv = new byte[16];
  int bufferSize = 2048;
  int bufferSizeLess = bufferSize - 1;
  int bufferSizeMore = bufferSize + 1;
  int length = 1024;
  int lengthLess = length - 1;
  int lengthMore = length + 1;

  private final String jceCipherClass = JceCipher.class.getName();
  private final String opensslCipherClass = OpensslCipher.class.getName();
  private CipherTransformation transformation =
                                CipherTransformation.AES_CTR_NOPADDING;

  @Before
  public void before() throws IOException {
    Random random = new SecureRandom();
    random.nextBytes(testData);
    random.nextBytes(key);
    random.nextBytes(iv);
    prepareData();
  }

  private void prepareData() throws IOException {
    Cipher cipher = null;
    try {
      cipher = (Cipher)ReflectionUtils.newInstance(
              ReflectionUtils.getClassByName(jceCipherClass),
              props, transformation);
    } catch (ClassNotFoundException cnfe) {
      throw new IOException("Illegal crypto cipher!");
    }

    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    // encryption data
    OutputStream out = new CryptoOutputStream(baos, cipher, bufferSize, key, iv);
    out.write(testData);
    out.flush();
    out.close();
    encData = baos.toByteArray();
  }

  public void setUp() throws IOException {}

  private PositionedCryptoInputStream getCryptoInputStream(Cipher cipher,
      int bufferSize) throws IOException {
    return new PositionedCryptoInputStream(new PositionedInputForTest(
      Arrays.copyOf(encData, encData.length)), cipher, bufferSize, key, iv, 0);
  }

  @Test
  public void doTest() throws Exception {
    testCipher(jceCipherClass);
    testCipher(opensslCipherClass);
  }

  private void testCipher(String cipherClass) throws Exception {
    doPositionedReadTests(cipherClass);
    doReadFullyTests(cipherClass);
    doSeekTests(cipherClass);
    doMultipleReadTest(cipherClass);
  }

  // when there are multiple positioned read actions and one read action,
  // they will not interfere each other.
  private void doMultipleReadTest(String cipherClass) throws Exception {
    PositionedCryptoInputStream in = getCryptoInputStream(
            getCipher(cipherClass), bufferSize);
    int position = 0;
    while (in.available() > 0) {
      ByteBuffer buf = ByteBuffer.allocate(length);
      byte[] bytes1 = new byte[length];
      byte[] bytes2 = new byte[lengthLess];
      // do the read and position read
      int pn1 = in.read(position, bytes1, 0, length);
      int n = in.read(buf);
      int pn2 = in.read(position, bytes2, 0, lengthLess);

      // verify the result
      if (pn1 > 0) {
        compareByteArray(testData, position, bytes1, pn1);
      }

      if (pn2 > 0) {
        compareByteArray(testData, position, bytes2, pn2);
      }

      if (n > 0) {
        compareByteArray(testData, position, buf.array(), n);
        position += n;
      } else {
        break;
      }
    }
    in.close();
  }

  private void doPositionedReadTests(String cipherClass) throws Exception {
    // test with different bufferSize when position = 0
    testPositionedReadLoop(cipherClass, 0, length, bufferSize, dataLen);
    testPositionedReadLoop(cipherClass, 0, length, bufferSizeLess, dataLen);
    testPositionedReadLoop(cipherClass, 0, length, bufferSizeMore, dataLen);
    // test with different position when bufferSize = 2048
    testPositionedReadLoop(cipherClass, dataLen / 2, length, bufferSize, dataLen);
    testPositionedReadLoop(cipherClass, dataLen / 2 - 1, length,
            bufferSizeLess, dataLen);
    testPositionedReadLoop(cipherClass, dataLen / 2 + 1, length,
            bufferSizeMore, dataLen);
    // position = -1 or position = max length, read nothing and return -1
    testPositionedReadNone(cipherClass, -1, length, bufferSize);
    testPositionedReadNone(cipherClass, dataLen, length, bufferSize);
  }

  private void doReadFullyTests(String cipherClass) throws Exception {
    // test with different bufferSize when position = 0
    testReadFullyLoop(cipherClass, 0, length, bufferSize, dataLen);
    testReadFullyLoop(cipherClass, 0, length, bufferSizeLess, dataLen);
    testReadFullyLoop(cipherClass, 0, length, bufferSizeMore, dataLen);
    // test with different length when position = 0
    testReadFullyLoop(cipherClass, 0, length, bufferSize, dataLen);
    testReadFullyLoop(cipherClass, 0, lengthLess, bufferSize, dataLen);
    testReadFullyLoop(cipherClass, 0, lengthMore, bufferSize, dataLen);
    // test read fully failed
    testReadFullyFailed(cipherClass, -1, length, bufferSize);
    testReadFullyFailed(cipherClass, dataLen, length, bufferSize);
    testReadFullyFailed(cipherClass, dataLen - length + 1, length, bufferSize);
  }

  private void doSeekTests(String cipherClass) throws Exception {
    // test with different length when position = 0
    testSeekLoop(cipherClass, 0, length, bufferSize);
    testSeekLoop(cipherClass, 0, lengthLess, bufferSize);
    testSeekLoop(cipherClass, 0, lengthMore, bufferSize);
    // there should be none data read when position = dataLen
    testSeekLoop(cipherClass, dataLen, length, bufferSize);
    // test exception when position = -1
    testSeekFailed(cipherClass, -1, bufferSize);
  }

  private void testSeekLoop(String cipherClass, int position, int length,
      int bufferSize) throws Exception {
    PositionedCryptoInputStream in = getCryptoInputStream(
            getCipher(cipherClass), bufferSize);
    while (in.available() > 0) {
      in.seek(position);
      ByteBuffer buf = ByteBuffer.allocate(length);
      int n = in.read(buf);
      if (n > 0) {
        compareByteArray(testData, position, buf.array(), n);
        position += n;
      } else {
        break;
      }
    }
    in.close();
  }

  // test for the out of index position, eg, -1.
  private void testSeekFailed(String cipherClass, int position,
      int bufferSize) throws Exception {
    PositionedCryptoInputStream in = getCryptoInputStream(
            getCipher(cipherClass), bufferSize);
    try {
      in.seek(position);
      Assert.fail("Excepted exception for cannot seek to negative offset.");
    } catch (IllegalArgumentException iae) {
    }
    in.close();
  }

  private void testPositionedReadLoop(String cipherClass, int position,
      int length, int bufferSize, int total) throws Exception {
    PositionedCryptoInputStream in = getCryptoInputStream(
            getCipher(cipherClass), bufferSize);
    // do the position read until the end of data
    while (position < total) {
      byte[] bytes = new byte[length];
      int n = in.read(position, bytes, 0, length);
      if (n >= 0) {
        compareByteArray(testData, position, bytes, n);
        position += n;
      } else {
        break;
      }
    }
    in.close();
  }

  // test for the out of index position, eg, -1.
  private void testPositionedReadNone(String cipherClass, int position,
      int length, int bufferSize) throws Exception {
    PositionedCryptoInputStream in = getCryptoInputStream(
            getCipher(cipherClass), bufferSize);
    byte[] bytes = new byte[length];
    int n = in.read(position, bytes, 0, length);
    Assert.assertEquals(n, -1);
    in.close();
  }

  private void testReadFullyLoop(String cipherClass,int position,
      int length, int bufferSize, int total) throws Exception {
    PositionedCryptoInputStream in = getCryptoInputStream(
            getCipher(cipherClass), bufferSize);

    // do the position read full until remain < length
    while (position + length <= total) {
      byte[] bytes = new byte[length];
      in.readFully(position, bytes, 0, length);
      compareByteArray(testData, position, bytes, length);
      position += length;
    }

    in.close();
  }

  // test for the End of file reached before reading fully
  private void testReadFullyFailed(String cipherClass, int position,
      int length, int bufferSize) throws Exception {
    PositionedCryptoInputStream in = getCryptoInputStream(
            getCipher(cipherClass), bufferSize);
    byte[] bytes = new byte[length];
    try {
      in.readFully(position, bytes, 0, length);
      Assert.fail("Excepted EOFException.");
    } catch (IOException ioe) {
      // excepted exception
    }
    in.close();
  }

  // compare the data from pos with length and data2 from 0 with length
  private void compareByteArray(byte[] data1, int pos, byte[] data2, int length) {
    byte[] expectedData = new byte[length];
    byte[] realData = new byte[length];
    // get the expected data with the position and length
    System.arraycopy(data1, pos, expectedData, 0, length);
    // get the real data
    System.arraycopy(data2, 0, realData, 0, length);
    Assert.assertArrayEquals(expectedData, realData);
  }

  private Cipher getCipher(String cipherClass) throws IOException {
    try {
      return (Cipher)ReflectionUtils.newInstance(
          ReflectionUtils.getClassByName(cipherClass), props, transformation);
    } catch (ClassNotFoundException cnfe) {
      throw new IOException("Illegal crypto cipher!");
    }
  }

  class PositionedInputForTest implements Input {

    byte[] data;
    long pos;
    long count;

    public PositionedInputForTest(byte[] data) {
      this.data = data;
      this.pos = 0;
      this.count = data.length;
    }

    @Override
    public int read(ByteBuffer dst) throws IOException {
      int remaining = (int)(count - pos);
      if(remaining <= 0) {
        return -1;
      }

      int length = Math.min(dst.remaining(), remaining);
      dst.put(data, (int)pos, length);
      pos += length;
      return length;
    }

    @Override
    public long skip(long n) throws IOException {
      if (n <= 0) {
        return 0;
      }

      long remaining = count - pos;
      if(remaining < n) {
        n = remaining;
      }
      pos += n;

      return n;
    }

    @Override
    public int read(long position, byte[] buffer, int offset, int length)
            throws IOException {
      if (buffer == null) {
        throw new NullPointerException();
      } else if (offset < 0 || length < 0 || length > buffer.length - offset) {
        throw new IndexOutOfBoundsException();
      }

      if (position < 0 || position >= count) {
        return -1;
      }

      long avail = count - position;
      if (length > avail) {
        length = (int)avail;
      }
      if (length <= 0) {
        return 0;
      }
      System.arraycopy(data, (int)position, buffer, offset, length);
      return length;
    }

    @Override
    public void seek(long position) throws IOException {
      if (pos < 0) {
        throw new IOException("Negative seek offset");
      } else if (position >= 0 && position < count) {
        pos = position;
      } else {
        // to the end of file
        pos = count;
      }
    }

    @Override
    public void close() throws IOException {
    }

    @Override
    public int available() throws IOException {
      return (int)(count - pos);
    }
  }
}
