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
package org.apache.commons.crypto.cipher;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Properties;
import java.util.Random;
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.crypto.conf.ConfigurationKeys;
import org.apache.commons.crypto.utils.ReflectionUtils;
import org.apache.commons.crypto.utils.Utils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public abstract class AbstractCipherTest {

  // data
  public static final int BYTEBUFFER_SIZE = 1000;
  public String[] cipherTests = null;
  Properties props = null;
  String cipherClass = null;
  CipherTransformation[] transformations = null;

  // cipher
  static final byte[] KEY = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
      0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16};
  static final byte[] IV = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
      0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
  Cipher enc, dec;

  @Before
  public void setup() {
    init();
    Utils.checkNotNull(cipherClass);
    Utils.checkNotNull(transformations);
    props = new Properties();
    props.setProperty(ConfigurationKeys.COMMONS_CRYPTO_CIPHER_CLASSES_KEY,
        cipherClass);
  }

  protected abstract void init() ;

  @Test
  public void cryptoTest() throws GeneralSecurityException, IOException {
    for (CipherTransformation tran : transformations) {
      /** uses the small data set in {@link TestData} */
      cipherTests = TestData.getTestData(tran);
      for (int i = 0; i != cipherTests.length; i += 5) {
        byte[] key = DatatypeConverter.parseHexBinary(cipherTests[i + 1]);
        byte[] iv = DatatypeConverter.parseHexBinary(cipherTests[i + 2]);

        byte[] inputBytes = DatatypeConverter.parseHexBinary(cipherTests[i + 3]);
        byte[] outputBytes = DatatypeConverter.parseHexBinary(cipherTests[i + 4]);

        ByteBuffer inputBuffer = ByteBuffer.allocateDirect(inputBytes.length);
        ByteBuffer outputBuffer = ByteBuffer.allocateDirect(outputBytes.length);
        inputBuffer.put(inputBytes);
        inputBuffer.flip();
        outputBuffer.put(outputBytes);
        outputBuffer.flip();

        byteBufferTest(tran,key, iv, inputBuffer, outputBuffer);
        byteArrayTest(tran, key, iv, inputBytes, outputBytes);
      }

      /** uses randomly generated big data set */
      byteArrayTest(tran, KEY, IV);
    }
  }

  private void byteBufferTest(CipherTransformation transformation, byte[] key,
                              byte[] iv,
                                ByteBuffer input, ByteBuffer output) throws
      GeneralSecurityException, IOException {
    ByteBuffer decResult = ByteBuffer.allocateDirect(BYTEBUFFER_SIZE);
    ByteBuffer encResult = ByteBuffer.allocateDirect(BYTEBUFFER_SIZE);
    Cipher enc, dec;

    enc = getCipher(transformation);
    dec = getCipher(transformation);

    try {
      enc.init(Cipher.ENCRYPT_MODE, key, iv);
    } catch (Exception e) {
      Assert.fail("AES failed initialisation - " + e.toString());
    }

    try {
      dec.init(Cipher.DECRYPT_MODE, key, iv);
    } catch (Exception e) {
      Assert.fail("AES failed initialisation - " + e.toString());
    }

    //
    // encryption pass
    //
    enc.doFinal(input, encResult);
    input.flip();
    encResult.flip();
    if (!output.equals(encResult)) {
      byte[] b = new byte[output.remaining()];
      output.get(b);
      byte[] c = new byte[encResult.remaining()];
      encResult.get(c);
      Assert.fail("AES failed encryption - expected " + new String(
          DatatypeConverter
              .printHexBinary(b)) + " got " + new String(
          DatatypeConverter.printHexBinary(c)));
    }

    //
    // decryption pass
    //
    dec.doFinal(encResult, decResult);
    decResult.flip();

    if (!input.equals(decResult)) {
      byte[] inArray = new byte[input.remaining()];
      byte[] decResultArray = new byte[decResult.remaining()];
      input.get(inArray);
      decResult.get(decResultArray);
      Assert.fail();
    }
  }

  /** test byte array whose data is planned in {@link TestData} */
  private void byteArrayTest(CipherTransformation transformation, byte[] key,
      byte[] iv, byte[] input, byte[] output) throws GeneralSecurityException {
    resetCipher(transformation, key, iv);
    int blockSize = transformation.getAlgorithmBlockSize();

    byte[] temp = new byte[input.length + blockSize];
    int n = enc.doFinal(input, 0, input.length, temp, 0);
    byte[] cipherText = new byte[n];
    System.arraycopy(temp, 0, cipherText, 0, n);
    Assert.assertArrayEquals("byte array encryption error.", output, cipherText);

    temp = new byte[cipherText.length + blockSize];
    int m = dec.doFinal(cipherText, 0, cipherText.length, temp, 0);
    byte[] plainText = new byte[m];
    System.arraycopy(temp, 0, plainText, 0, m);
    Assert.assertArrayEquals("byte array decryption error.", input, plainText);
  }

  /** test byte array whose data is randomly generated */
  private void byteArrayTest(CipherTransformation transformation, byte[] key,
      byte[] iv) throws GeneralSecurityException {
    int blockSize = transformation.getAlgorithmBlockSize();

    // AES_CBC_NOPADDING only accepts data whose size is the multiple of block size
    int[] dataLenList = (transformation == CipherTransformation.AES_CBC_NOPADDING)
        ? new int[] {10 * 1024} : new int[] {10 * 1024, 10 * 1024 - 3};
    for (int dataLen : dataLenList) {
      byte[] plainText = new byte[dataLen];
      Random random = new SecureRandom();
      random.nextBytes(plainText);
      byte[] cipherText = new byte[dataLen + blockSize];

      // check update method with inputs whose sizes are the multiple of block size or not
      int[] bufferLenList = new int[] {2 * 1024 - 128, 2 * 1024 - 125};
      for (int bufferLen : bufferLenList) {
        resetCipher(transformation, key, iv);

        int offset = 0;
        // encrypt (update + doFinal) the data
        int cipherPos = 0;
        for (int i = 0; i < dataLen / bufferLen; i ++) {
          cipherPos += enc.update(plainText, offset, bufferLen, cipherText, cipherPos);
          offset += bufferLen;
        }
        cipherPos += enc.doFinal(plainText, offset, dataLen % bufferLen, cipherText, cipherPos);

        offset = 0;
        // decrypt (update + doFinal) the data
        byte[] realPlainText = new byte[cipherPos + blockSize];
        int plainPos = 0;
        for (int i = 0; i < cipherPos / bufferLen; i ++) {
          plainPos += dec.update(cipherText, offset, bufferLen, realPlainText, plainPos);
          offset += bufferLen;
        }
        plainPos += dec.doFinal(cipherText, offset, cipherPos % bufferLen, realPlainText, plainPos);

        // verify
        Assert.assertEquals("random byte array length changes after transformation",
            dataLen, plainPos);

        byte[] shrinkPlainText = new byte[plainPos];
        System.arraycopy(realPlainText, 0, shrinkPlainText, 0, plainPos);
        Assert.assertArrayEquals("random byte array contents changes after transformation",
            plainText, shrinkPlainText);
      }
    }
  }

  private void resetCipher(CipherTransformation transformation, byte[] key, byte[] iv) {
    enc = getCipher(transformation);
    dec = getCipher(transformation);

    try {
      enc.init(Cipher.ENCRYPT_MODE, key, iv);
    } catch (Exception e) {
      Assert.fail("AES failed initialisation - " + e.toString());
    }

    try {
      dec.init(Cipher.DECRYPT_MODE, key, iv);
    } catch (Exception e) {
      Assert.fail("AES failed initialisation - " + e.toString());
    }
  }

  private Cipher getCipher(CipherTransformation transformation) {
    try {
      return (Cipher) ReflectionUtils
          .newInstance(ReflectionUtils.getClassByName(cipherClass), props,
              transformation);
    } catch (ClassNotFoundException e) {
      throw new RuntimeException(e);
    }

  }
}