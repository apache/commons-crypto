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
package com.intel.chimera.crypto;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Properties;

import com.google.common.base.Preconditions;

/**
 * Implement the Cipher using JNI into OpenSSL.
 */
public class OpensslCipher implements Cipher {
  private final CipherTransformation transformation;
  private final Openssl cipher;

  /**
   * Constructs a {@link com.intel.chimera.crypto.Cipher} using JNI into OpenSSL
   * @param props properties for OpenSSL cipher
   * @param transformation transformation for OpenSSL cipher
   * @throws GeneralSecurityException if OpenSSL cipher initialize failed
   */
  public OpensslCipher(Properties props, CipherTransformation transformation)
      throws GeneralSecurityException {
    this.transformation = transformation;

    String loadingFailureReason = Openssl.getLoadingFailureReason();
    if (loadingFailureReason != null) {
      throw new RuntimeException(loadingFailureReason);
    }

    cipher = Openssl.getInstance(transformation.getName());
  }

  @Override
  public CipherTransformation getTransformation() {
    return transformation;
  }

  /**
   * Initializes the cipher with mode, key and iv.
   * @param mode {@link #ENCRYPT_MODE} or {@link #DECRYPT_MODE}
   * @param key crypto key for the cipher
   * @param iv Initialization vector for the cipher
   * @throws IOException if cipher initialize fails
   */
  @Override
  public void init(int mode, byte[] key, byte[] iv) throws IOException {
    Preconditions.checkNotNull(key);
    Preconditions.checkNotNull(iv);

    int cipherMode = Openssl.DECRYPT_MODE;
    if(mode == ENCRYPT_MODE)
      cipherMode = Openssl.ENCRYPT_MODE;

    cipher.init(cipherMode, key, iv);
  }

  /**
   * Continues a multiple-part encryption/decryption operation. The data
   * is encrypted or decrypted, depending on how this cipher was initialized.
   * @param inBuffer the input ByteBuffer
   * @param outBuffer the output ByteBuffer
   * @return int number of bytes stored in <code>output</code>
   * @throws IOException if cipher failed to update, for example, there is
   * insufficient space in the output buffer
   */
  @Override
  public int update(ByteBuffer inBuffer, ByteBuffer outBuffer) throws IOException {
    try {
      return cipher.update(inBuffer, outBuffer);
    } catch (Exception e) {
      throw new IOException(e);
    }
  }

  /**
   * Encrypts or decrypts data in a single-part operation, or finishes a
   * multiple-part operation. The data is encrypted or decrypted, depending
   * on how this cipher was initialized.
   * @param inBuffer the input ByteBuffer
   * @param outBuffer the output ByteBuffer
   * @return int number of bytes stored in <code>output</code>
   * @throws IOException if cipher failed to update, for example, there is
   * insufficient space in the output buffer
   */
  @Override
  public int doFinal(ByteBuffer inBuffer, ByteBuffer outBuffer) throws IOException {
    try {
      int n = cipher.update(inBuffer, outBuffer);
      return n + cipher.doFinal(outBuffer);
    } catch (Exception e) {
      throw new IOException(e);
    }
  }

  /**
   * Closes the OpenSSL cipher. Clean the Openssl native context.
   */
  @Override
  public void close() {
    cipher.clean();
  }
}
