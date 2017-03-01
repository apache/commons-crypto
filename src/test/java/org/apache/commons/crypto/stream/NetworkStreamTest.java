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
package org.apache.commons.crypto.stream;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.SecureRandom;
import java.util.Iterator;
import java.util.Properties;
import java.util.Random;
import java.util.Set;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.crypto.cipher.AbstractCipherTest;
import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.utils.ReflectionUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class NetworkStreamTest extends Thread {
  private final int dataLen = 10000;
  private byte[] data = new byte[dataLen];
  private ByteBuffer rawData;
  private ByteBuffer encryptedData;
  private Properties props = new Properties();
  protected byte[] key = new byte[16];
  protected byte[] iv = new byte[16];
  protected static int defaultBufferSize = 8192;
  protected String transformation;
  protected Thread serverThread;

  @Before
  public void before() throws IOException {
    Random random = new SecureRandom();
    random.nextBytes(data);
    random.nextBytes(key);
    random.nextBytes(iv);
    transformation = "AES/CTR/NoPadding";
    encryptedData = ByteBuffer.allocate(dataLen);
    encryptedData.clear();
    startServer();
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
          ServerSocketChannel server = ServerSocketChannel.open();
          server.configureBlocking(false);
          server.socket().bind(new InetSocketAddress("localhost", 9999));
          Selector selector = Selector.open();

          int ops = server.validOps();
          server.register(selector,ops, null);

          int total_bytes_read = 0;

          while (total_bytes_read < dataLen) {
            selector.select();
            Set<SelectionKey> readyKeys = selector.selectedKeys();
            Iterator<SelectionKey> keyIterator = readyKeys.iterator();

            while (keyIterator.hasNext()) {
              SelectionKey skey = keyIterator.next();
              if (skey.isAcceptable()) {
                SocketChannel clientSocket = server.accept();
                clientSocket.configureBlocking(false);
                clientSocket.register(selector,SelectionKey.OP_READ);

              } else if (skey.isReadable()) {
                CryptoInputStream cis = new CryptoInputStream((SocketChannel) skey.channel(),
                  getCipher(AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME),
                  defaultBufferSize, new SecretKeySpec(key, "AES"),
                  new IvParameterSpec(iv));

                int read = 0;
                while ((read = cis.read(encryptedData)) > 0) {
                  total_bytes_read += read;
                }
                cis.close();
              }
              keyIterator.remove();
            }
          }
        }
        catch (IOException e) {
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
    sleep(1000);
    SocketChannel client = SocketChannel.open();
    client.connect(new InetSocketAddress("localhost", 9999));
    CryptoOutputStream cos = new CryptoOutputStream(client,
      getCipher(AbstractCipherTest.OPENSSL_CIPHER_CLASSNAME),
      defaultBufferSize, new SecretKeySpec(key, "AES"),
      new IvParameterSpec(iv));
    rawData = ByteBuffer.wrap(data);

    while (rawData.hasRemaining()) {
      cos.write(rawData);
    }
    serverThread.join();
    cos.close();
    Assert.assertArrayEquals("Data not equal", rawData.array(), encryptedData.array());
  }
}
