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
import java.security.SecureRandom;
import java.util.Properties;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.google.common.base.Preconditions;
import com.intel.chimera.utils.Utils;

/**
 * Implement the {@link com.intel.chimera.crypto.Cipher} using JCE provider.
 */
public class JceCipher implements Cipher {
  private static final Log LOG = LogFactory.getLog(JceCipher.class.getName());

  private final String provider;
  private final CipherTransformation transformation;
  private final javax.crypto.Cipher cipher;
  private SecureRandom random;

  /**
   * Constructs a {@link com.intel.chimera.crypto.Cipher} based on JCE
   * Cipher {@link javax.crypto.Cipher}.
   * @param props properties for JCE cipher
   * @param transformation transformation for JCE cipher
   * @throws GeneralSecurityException if JCE cipher initialize failed
   */
  public JceCipher(Properties props, CipherTransformation transformation)
      throws GeneralSecurityException {
    this.provider = Utils.getJCEProvider(props);
    this.transformation = transformation;

    final String secureRandomAlg = Utils.getSecureRandomAlg(props);
    try {
      random = (provider != null) ?
          SecureRandom.getInstance(secureRandomAlg, provider) :
            SecureRandom.getInstance(secureRandomAlg);
    } catch (GeneralSecurityException e) {
      LOG.warn(e.getMessage());
      random = new SecureRandom();
    }

    if (provider == null || provider.isEmpty()) {
      cipher = javax.crypto.Cipher.getInstance(transformation.getName());
    } else {
      cipher = javax.crypto.Cipher.getInstance(transformation.getName(), provider);
    }
  }

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
  public void init(int mode, byte[] key, byte[] iv) throws IOException {
    Preconditions.checkNotNull(key);
    Preconditions.checkNotNull(iv);

    int cipherMode = javax.crypto.Cipher.DECRYPT_MODE;
    if(mode == ENCRYPT_MODE)
      cipherMode = javax.crypto.Cipher.ENCRYPT_MODE;

    try {
      cipher.init(cipherMode, new SecretKeySpec(key, "AES"),
          new IvParameterSpec(iv));
    } catch (Exception e) {
      throw new IOException(e);
    }
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
  public int doFinal(ByteBuffer inBuffer, ByteBuffer outBuffer) throws IOException {
    try {
      return cipher.doFinal(inBuffer, outBuffer);
    } catch(Exception e) {
      throw new IOException(e);
    }
  }

  /**
   * Generates a number of secure, random bytes suitable for cryptographic use.
   * This method needs to be thread-safe.
   *
   * @param bytes byte array to populate with random data
   */
  public void generateSecureRandom(byte[] bytes) {
    random.nextBytes(bytes);
  }
}
