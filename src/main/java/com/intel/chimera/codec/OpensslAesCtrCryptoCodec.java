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
package com.intel.chimera.codec;

import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Properties;
import java.util.Random;

import com.google.common.base.Preconditions;
import com.intel.chimera.utils.Utils;

/**
 * Implement the AES-CTR crypto codec using JNI into OpenSSL.
 */
public class OpensslAesCtrCryptoCodec extends AesCtrCryptoCodec {
  private Random random;

  public OpensslAesCtrCryptoCodec(Properties props) {
    String loadingFailureReason = OpensslCipher.getLoadingFailureReason();
    if (loadingFailureReason != null) {
      throw new RuntimeException(loadingFailureReason);
    }

    random = Utils.getSecureRandom(props);
  }

  @Override
  protected void finalize() throws Throwable {
    try {
      Closeable r = (Closeable) this.random;
      r.close();
    } catch (ClassCastException e) {
    }
    super.finalize();
  }

  @Override
  public Encryptor createEncryptor() throws GeneralSecurityException {
    return new OpensslAesCtrCipher(OpensslCipher.ENCRYPT_MODE);
  }

  @Override
  public Decryptor createDecryptor() throws GeneralSecurityException {
    return new OpensslAesCtrCipher(OpensslCipher.DECRYPT_MODE);
  }
  
  @Override
  public void generateSecureRandom(byte[] bytes) {
    random.nextBytes(bytes);
  }
  
  private static class OpensslAesCtrCipher implements Encryptor, Decryptor {
    private final OpensslCipher cipher;
    private final int mode;
    private boolean contextReset = false;
    
    public OpensslAesCtrCipher(int mode) throws GeneralSecurityException {
      this.mode = mode;
      cipher = OpensslCipher.getInstance(SUITE.getName());
    }

    @Override
    public void init(byte[] key, byte[] iv) throws IOException {
      Preconditions.checkNotNull(key);
      Preconditions.checkNotNull(iv);
      contextReset = false;
      cipher.init(mode, key, iv);
    }
    
    /**
     * AES-CTR will consume all of the input data. It requires enough space in 
     * the destination buffer to encrypt entire input buffer.
     */
    @Override
    public void encrypt(ByteBuffer inBuffer, ByteBuffer outBuffer)
        throws IOException {
      process(inBuffer, outBuffer);
    }
    
    /**
     * AES-CTR will consume all of the input data. It requires enough space in
     * the destination buffer to decrypt entire input buffer.
     */
    @Override
    public void decrypt(ByteBuffer inBuffer, ByteBuffer outBuffer)
        throws IOException {
      process(inBuffer, outBuffer);
    }
    
    @Override
    public boolean isContextReset() {
      return contextReset;
    }
    
    private void process(ByteBuffer inBuffer, ByteBuffer outBuffer)
        throws IOException {
      try {
        int inputSize = inBuffer.remaining();
        // OpensslCipher#update will maintain crypto context.
        int n = cipher.update(inBuffer, outBuffer);
        if (n < inputSize) {
          /**
           * Typically code will not get here. OpensslCipher#update will 
           * consume all input data and put result in outBuffer. 
           * OpensslCipher#doFinal will reset the crypto context.
           */
          contextReset = true;
          cipher.doFinal(outBuffer);
        }
      } catch (Exception e) {
        throw new IOException(e);
      }
    }
  }
}
