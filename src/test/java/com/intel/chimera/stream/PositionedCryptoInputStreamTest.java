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
import com.intel.chimera.utils.ReflectionUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.Properties;
import java.util.Random;

public class PositionedCryptoInputStreamTest {

  private static final Log LOG= LogFactory.getLog(PositionedCryptoInputStreamTest.class);


  private final int dataLen = 20000;
  private byte[] data = new byte[dataLen];
  private byte[] encData;
  private Properties props = new Properties();
  private byte[] key = new byte[16];
  private byte[] iv = new byte[16];
  private static int defaultBufferSize = 8192;

  private final String jceCipherClass = JceCipher.class.getName();
  private final String opensslCipherClass = OpensslCipher.class.getName();
  private CipherTransformation transformation = CipherTransformation.AES_CTR_NOPADDING;
  private Path testDataFilepath;

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
    OutputStream out = new CryptoOutputStream(baos, cipher, defaultBufferSize, key, iv);
    out.write(data);
    out.flush();
    out.close();
    encData = baos.toByteArray();

    // create the file with the encryption data for the test
    try {
      testDataFilepath = Files.createTempFile("encData", ".tmp");
      SeekableByteChannel sbc = Files.newByteChannel(testDataFilepath, StandardOpenOption.APPEND);
      ByteBuffer bfSrc = ByteBuffer.wrap(encData);
      sbc.write(bfSrc);
      sbc.close();
    } catch (IOException ioe) {
      LOG.error("Error when prepare file with encryption data.", ioe);
    }
  }

  private CryptoInputStream getCryptoInputStream(Cipher cipher, int bufferSize,byte[] iv)
          throws IOException {
    return new PositionedCryptoInputStream(Files.newByteChannel(testDataFilepath, StandardOpenOption.READ), cipher,
            bufferSize, key, iv, 0);
  }

  @After
  public void deleteTempFile() throws Exception {
    if (Files.exists(testDataFilepath)) {
      Files.delete(testDataFilepath);
    }
  }

  @Test
  public void testPositionedRead() throws Exception {
    doPositionedRead(jceCipherClass);
    doPositionedRead(opensslCipherClass);
  }

  private void doPositionedRead(String cipherClass) throws Exception {
    InputStream in = getCryptoInputStream(getCipher(cipherClass), defaultBufferSize, iv);
    int positionedReadLength = 100;
    ByteBuffer buf = ByteBuffer.allocate(positionedReadLength);
    allReadTests(in, buf, positionedReadLength);
    allReadFullyTests(in, buf, positionedReadLength);
    allSeekTests(in, positionedReadLength);
    in.close();
  }

  private void allReadTests(InputStream in, ByteBuffer buf, int positionedReadLength) throws Exception {
    positionedReadCheck(in, buf.array(), 0, 0, positionedReadLength);
    positionedReadCheck(in, buf.array(), defaultBufferSize - 1, 0, positionedReadLength);
    positionedReadCheck(in, buf.array(), defaultBufferSize, 0, positionedReadLength);
    positionedReadCheck(in, buf.array(), -1, 0, positionedReadLength);
    positionedReadCheck(in, buf.array(), dataLen - positionedReadLength, 0, positionedReadLength);
    positionedReadCheck(in, buf.array(), dataLen, 0, positionedReadLength);
    positionedReadCheck(in, buf.array(), dataLen - 1, 0, positionedReadLength);
    positionedReadCheck(in, buf.array(), dataLen - positionedReadLength/2, 0, positionedReadLength);
  }

  private void allReadFullyTests(InputStream in, ByteBuffer buf, int positionedReadLength) throws Exception {
    positionedReadFullyCheck(in, buf.array(), 0, 0, positionedReadLength);
    positionedReadFullyCheck(in, buf.array(), defaultBufferSize - 1, 0, positionedReadLength);
    positionedReadFullyCheck(in, buf.array(), defaultBufferSize, 0, positionedReadLength);
    positionedReadFullyCheck(in, buf.array(), dataLen - positionedReadLength, 0, positionedReadLength);

    try {
      positionedReadFullyCheck(in, buf.array(), -1, 0, positionedReadLength);
      Assert.fail("Excepted EOFException.");
    } catch (IOException ioe) {
      // excepted exception
    }

    try {
      positionedReadFullyCheck(in, buf.array(), dataLen, 0, positionedReadLength);
      Assert.fail("Excepted EOFException.");
    } catch (IOException ioe) {
      // excepted exception
    }

    try {
      positionedReadFullyCheck(in, buf.array(), dataLen - positionedReadLength/2, 0, positionedReadLength);
      Assert.fail("Excepted EOFException.");
    } catch (IOException ioe) {
      // excepted exception
    }
  }

  private void allSeekTests(InputStream in, int positionedReadLength) throws Exception {
    positionedSeekCheck(in, 0, positionedReadLength);
    positionedSeekCheck(in, defaultBufferSize - 1, positionedReadLength);
    positionedSeekCheck(in, defaultBufferSize, positionedReadLength);
    positionedSeekCheck(in, dataLen - positionedReadLength, positionedReadLength);
    positionedSeekCheck(in, dataLen - 1, positionedReadLength);
    positionedSeekCheck(in, dataLen - positionedReadLength/2, positionedReadLength);

    try {
      // the position can't be negative
      positionedSeekCheck(in, -1, positionedReadLength);
      Assert.fail("Excepted IllegalArgumentException.");
    } catch (IllegalArgumentException iae) {
      // excepted exception
    }

    try {
      // the position out of size, and the read() will return -1.
      positionedSeekCheck(in, dataLen, positionedReadLength);
      Assert.fail("Excepted NegativeArraySizeException.");
    } catch (NegativeArraySizeException naze) {
      // excepted exception
    }
  }

  private void positionedSeekCheck(InputStream in, int position, int length) throws Exception {
    PositionedCryptoInputStream positionedIn = (PositionedCryptoInputStream) in;
    positionedIn.seek(position);
    ByteBuffer buf = ByteBuffer.allocate(length);
    int n = positionedIn.read(buf);
    byteArrayCompare(n, buf.array(), position, length);
  }

  private void positionedReadCheck(InputStream in, byte[] buf,
                                   int position, int offset, int length) throws Exception {
    int n = ((PositionedCryptoInputStream) in).read(position, buf, offset, length);
    byteArrayCompare(n, buf, position, length);
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

  private void positionedReadFullyCheck(InputStream in, byte[] buf,
                                   int position, int offset, int length) throws Exception {
    ((PositionedCryptoInputStream) in).readFully(position, buf, offset, length);
    byte[] readData = new byte[length];
    byte[] expectedData = new byte[length];
    System.arraycopy(buf, 0, readData, 0, length);
    System.arraycopy(data, position, expectedData, 0, length);
    Assert.assertArrayEquals(expectedData, readData);
  }

  private Cipher getCipher(String cipherClass) throws IOException {
    try {
      return (Cipher)ReflectionUtils.newInstance(
              ReflectionUtils.getClassByName(cipherClass), props, transformation);
    } catch (ClassNotFoundException cnfe) {
      throw new IOException("Illegal crypto cipher!");
    }
  }
}
