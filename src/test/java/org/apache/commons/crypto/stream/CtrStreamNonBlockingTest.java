/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.commons.crypto.stream;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Properties;
import java.util.Random;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.crypto.cipher.AbstractCipherTest;
import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.utils.ReflectionUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class CtrStreamNonBlockingTest extends Thread {
  private final int dataLen = 10000;
  private byte[] data = new byte[dataLen];
  private ByteBuffer originData;
  private ByteBuffer receivedData;
  private Properties props = new Properties();
  private byte[] key = new byte[16];
  private byte[] iv = new byte[16];
  private String transformation;
  private Thread serverThread;
  private int defaultBufferSize = 8192;
  private DummyChannel dummyChannel;


  @Before
  public void before() throws IOException {
    Random random = new SecureRandom();
    random.nextBytes(data);
    random.nextBytes(key);
    random.nextBytes(iv);
    transformation = "AES/CTR/NoPadding";
    receivedData = ByteBuffer.allocate(dataLen);
    receivedData.clear();
    startServer();
    dummyChannel = new DummyChannel();
  }

  protected CryptoCipher getCipher(String cipherClass) throws IOException {
    try {
      return (CryptoCipher) ReflectionUtils.newInstance(
              ReflectionUtils.getClassByName(cipherClass), props,
              transformation);
    } catch (ClassNotFoundException cnfe) {
      throw new IOException("Illegal crypto cipher!");
    }
  }

  public void startServer() {

    Runnable serverTask = new Runnable() {
      @Override
      public void run() {
        try {
          CryptoInputStream cis = new CryptoInputStream(dummyChannel,
                  getCipher(AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME),
                  defaultBufferSize, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));

          while (cis.read(receivedData) != -1);
        } catch (Exception e) {
          e.printStackTrace();
        }
      }
    };

    serverThread = new Thread(serverTask);
    serverThread.start();
  }

  /** Test byte buffer write blocking */
  @Test(timeout = 120000)
  public void testByteBufferWriteBlocking() throws Exception {
    CryptoOutputStream cos = new CryptoOutputStream(dummyChannel,
            getCipher(AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME),
            defaultBufferSize, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
    originData = ByteBuffer.wrap(data);
    while (originData.hasRemaining()) {
      cos.write(originData);
    }

    cos.close();
    serverThread.join();
    Assert.assertArrayEquals("Data not equal", originData.array(), receivedData.array());
  }
}
