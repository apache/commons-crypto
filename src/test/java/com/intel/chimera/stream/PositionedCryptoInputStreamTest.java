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
import com.intel.chimera.input.Input;
import com.intel.chimera.utils.ReflectionUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Properties;
import java.util.Random;

public class PositionedCryptoInputStreamTest {

  private final int dataLen = 20000;
  private byte[] data = new byte[dataLen];
  private byte[] encData;
  private Properties props = new Properties();
  private byte[] key = new byte[16];
  private byte[] iv = new byte[16];
  private static int defaultBufferSize = 8192;
  private static int smallBufferSize = 1024;

  private final String jceCipherClass = JceCipher.class.getName();
  private final String opensslCipherClass = OpensslCipher.class.getName();
  private CipherTransformation transformation = CipherTransformation.AES_CTR_NOPADDING;

  @Before
  public void before() throws IOException {
    Random random = new SecureRandom();
    random.nextBytes(data);
    random.nextBytes(key);
    random.nextBytes(iv);
    prepareData();
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
    // encryption data
    OutputStream out = new CryptoOutputStream(baos, cipher, defaultBufferSize, key, iv);
    out.write(data);
    out.flush();
    out.close();
    encData = baos.toByteArray();
  }

  public void setUp() throws IOException {}

  private PositionedCryptoInputStream getCryptoInputStream(Cipher cipher, int bufferSize,byte[] iv)
          throws IOException {
    return new PositionedCryptoInputStream(new PositionedInputForTest(Arrays.copyOf(encData, encData.length),
            defaultBufferSize), cipher, bufferSize, key, iv, 0);
  }

  @Test
  public void doTest() throws Exception {
    doTest(jceCipherClass);
    doTest(opensslCipherClass);
  }

  private void doTest(String cipherClass) throws Exception {
    int positionedReadLength = 100;
    allBufferReadTests(cipherClass);
    allPositionedReadTests(cipherClass, positionedReadLength);
    allReadFullyTests(cipherClass, positionedReadLength);
    allSeekTests(cipherClass, positionedReadLength);
  }

  private void allPositionedReadTests(String cipherClass, int positionedReadLength) throws Exception {
    positionedReadCheck(cipherClass, 0, 0, positionedReadLength);
    positionedReadCheck(cipherClass, defaultBufferSize - 1, 0, positionedReadLength);
    positionedReadCheck(cipherClass, defaultBufferSize, 0, positionedReadLength);
    positionedReadCheck(cipherClass, dataLen - positionedReadLength, 0, positionedReadLength);
    positionedReadCheck(cipherClass, dataLen - 1, 0, positionedReadLength);
    positionedReadCheck(cipherClass, dataLen - positionedReadLength/2, 0, positionedReadLength);

    try {
      // -1 will be returned with the negative position, and NegativeArraySizeException will be thrown during the test.
      positionedReadCheck(cipherClass, -1, 0, positionedReadLength);
      Assert.fail("Excepted NegativeArraySizeException.");
    } catch (NegativeArraySizeException nase) {
     // excepted exception
    }

    try {
      // -1 will be returned, and NegativeArraySizeException will be thrown during the test.
      positionedReadCheck(cipherClass, dataLen, 0, positionedReadLength);
      Assert.fail("Excepted NegativeArraySizeException.");
    } catch (NegativeArraySizeException nase) {
      // excepted exception
    }
  }

  private void allReadFullyTests(String cipherClass, int positionedReadLength) throws Exception {
    positionedReadFullyCheck(cipherClass, 0, 0, positionedReadLength);
    positionedReadFullyCheck(cipherClass, defaultBufferSize - 1, 0, positionedReadLength);
    positionedReadFullyCheck(cipherClass, defaultBufferSize, 0, positionedReadLength);
    positionedReadFullyCheck(cipherClass, dataLen - positionedReadLength, 0, positionedReadLength);

    try {
      positionedReadFullyCheck(cipherClass, -1, 0, positionedReadLength);
      Assert.fail("Excepted EOFException.");
    } catch (IOException ioe) {
      // excepted exception
    }

    try {
      positionedReadFullyCheck(cipherClass, dataLen, 0, positionedReadLength);
      Assert.fail("Excepted EOFException.");
    } catch (IOException ioe) {
      // excepted exception
    }

    try {
      positionedReadFullyCheck(cipherClass, dataLen - positionedReadLength/2, 0, positionedReadLength);
      Assert.fail("Excepted EOFException.");
    } catch (IOException ioe) {
      // excepted exception
    }
  }

  private void allSeekTests(String cipherClass, int positionedReadLength) throws Exception {
    positionedSeekCheck(cipherClass, 0, positionedReadLength, positionedReadLength);
    positionedSeekCheck(cipherClass, defaultBufferSize - 1, positionedReadLength, positionedReadLength);
    positionedSeekCheck(cipherClass, defaultBufferSize, positionedReadLength, positionedReadLength);
    positionedSeekCheck(cipherClass, dataLen - positionedReadLength, positionedReadLength, positionedReadLength);
    positionedSeekCheck(cipherClass, dataLen - 1, positionedReadLength, 1);
    positionedSeekCheck(cipherClass, dataLen - positionedReadLength / 2, positionedReadLength, positionedReadLength / 2);
    positionedSeekCheck(cipherClass, dataLen, positionedReadLength, 0);
    try {
      // Cannot seek to negative offset
      positionedSeekCheck(cipherClass, -1, positionedReadLength, 0);
      Assert.fail("Excepted exception for cannot seek to negative offset.");
    } catch (IllegalArgumentException iae) {
    }
  }

  private void allBufferReadTests(String cipherClass) throws Exception {
    bufferReadCheck(cipherClass, defaultBufferSize, 0);
    bufferReadCheck(cipherClass, defaultBufferSize, 11);
    bufferReadCheck(cipherClass, smallBufferSize, 0);
    bufferReadCheck(cipherClass, smallBufferSize, 11);
  }

  private void positionedSeekCheck(String cipherClass, int position, int length, int exceptedLength) throws Exception {
    PositionedCryptoInputStream in = getCryptoInputStream(getCipher(cipherClass), defaultBufferSize, iv);
    in.seek(position);
    ByteBuffer buf = ByteBuffer.allocate(length);
    int n = in.read(buf);
    Assert.assertEquals(exceptedLength, n);
    byteArrayCompare(n, buf.array(), position, length);
    in.close();
  }

  private void positionedReadCheck(String cipherClass, int position, int offset, int length) throws Exception {
    PositionedCryptoInputStream in = getCryptoInputStream(getCipher(cipherClass), defaultBufferSize, iv);
    ByteBuffer buf = ByteBuffer.allocate(length);
    int n = in.read(position, buf.array(), offset, length);
    byteArrayCompare(n, buf.array(), position, length);
    in.close();
  }

  private void byteArrayCompare(int readLength, byte[] buf, int position, int length) {
    byte[] readData = new byte[readLength];
    byte[] expectedData = new byte[readLength];
    System.arraycopy(buf, 0, readData, 0, readLength);

    if (position < 0 || position > dataLen - 1) {
      Assert.assertArrayEquals(new byte[readLength], readData);
    } else if (position + length > dataLen) {
      System.arraycopy(data, position, expectedData, 0, dataLen - position);
      Assert.assertArrayEquals(expectedData, readData);
    } else {
      System.arraycopy(data, position, expectedData, 0, readLength);
      Assert.assertArrayEquals(expectedData, readData);
    }
  }

  private void positionedReadFullyCheck(String cipherClass,int position,
      int offset, int length) throws Exception {
    PositionedCryptoInputStream in = getCryptoInputStream(getCipher(cipherClass), defaultBufferSize, iv);
    ByteBuffer buf = ByteBuffer.allocate(length);
    in.readFully(position, buf.array(), offset, length);
    byte[] readData = new byte[length];
    byte[] expectedData = new byte[length];
    System.arraycopy(buf.array(), 0, readData, 0, length);
    System.arraycopy(data, position, expectedData, 0, length);
    Assert.assertArrayEquals(expectedData, readData);
  }

  private void bufferReadCheck(String cipherClass, int bufferSize, int bufPos) throws Exception {
    PositionedCryptoInputStream in = getCryptoInputStream(getCipher(cipherClass), bufferSize, iv);
    ByteBuffer buf = ByteBuffer.allocate(dataLen + 100);
    buf.position(bufPos);
    int n = in.read(buf);
    Assert.assertEquals(bufPos + n, buf.position());
    byte[] readData = new byte[n];
    buf.rewind();
    buf.position(bufPos);
    buf.get(readData);
    byte[] expectedData = new byte[n];
    System.arraycopy(data, 0, expectedData, 0, n);
    Assert.assertArrayEquals(readData, expectedData);
    in.close();
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
    byte[] buf;
    int bufferSize;

    public PositionedInputForTest(byte[] data, int bufferSize) {
      this.data = data;
      this.pos = 0;
      this.count = data.length;
      this.bufferSize = bufferSize;
    }

    @Override
    public int read(ByteBuffer dst) throws IOException {
      int remaining = dst.remaining();
      final byte[] tmp = getBuf();
      int read = 0;
      int offset = 0;
      while (remaining > 0) {
        int copyLen = Math.min(Math.min(remaining, bufferSize), available());
        if (copyLen == 0) {
          break;
        }
        System.arraycopy(data, (int)pos, tmp, 0, copyLen);
        dst.put(tmp, offset, copyLen);
        read += copyLen;
        offset += copyLen;
        pos += copyLen;
        remaining -= copyLen;
      }
      return read;
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
    public void readFully(long position, byte[] buffer, int offset, int length)
            throws IOException {
      int nread = 0;
      while (nread < length) {
        int nbytes = read(position+nread, buffer, offset+nread, length-nread);
        if (nbytes < 0) {
          throw new EOFException("End of file reached before reading fully.");
        }
        nread += nbytes;
      }
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

    private byte[] getBuf() {
      if (buf == null) {
        buf = new byte[bufferSize];
      }
      return buf;
    }
  }
}
