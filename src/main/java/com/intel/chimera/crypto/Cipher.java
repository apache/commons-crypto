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
import java.util.List;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Splitter;
import com.google.common.collect.Lists;
import com.intel.chimera.utils.Utils;
import com.intel.chimera.utils.ReflectionUtils;

/**
 * This interface of a cryptographic cipher for encryption and decryption.
 */
public interface Cipher {
  // The mode constant to be used when calling init method of the Cipher
  int ENCRYPT_MODE = 1;
  int DECRYPT_MODE = 0;

  /**
   * @return the CipherTransformation for this cipher.
   */
  CipherTransformation getTransformation();

  /**
   * Initializes the cipher with mode, key and iv.
   * @param mode {@link #ENCRYPT_MODE} or {@link #DECRYPT_MODE}
   * @param key crypto key for the cipher
   * @param iv Initialization vector for the cipher
   * @throws IOException if cipher initialize fails
   */
  void init(int mode, byte[] key, byte[] iv) throws IOException;

  /**
   * Continues a multiple-part encryption/decryption operation. The data
   * is encrypted or decrypted, depending on how this cipher was initialized.
   * @param inBuffer the input ByteBuffer
   * @param outBuffer the output ByteBuffer
   * @return int number of bytes stored in <code>output</code>
   * @throws IOException if cipher failed to update, for example, there is
   * * insufficient space in the output buffer
   */
  int update(ByteBuffer inBuffer, ByteBuffer outBuffer) throws IOException;

  /**
   * Encrypts or decrypts data in a single-part operation, or finishes a
   * multiple-part operation.
   * @param inBuffer the input ByteBuffer
   * @param outBuffer the output ByteBuffer
   * @return int number of bytes stored in <code>output</code>
   * @throws IOException if cipher failed to update, for example, there is
   * * insufficient space in the output buffer
   */
  int doFinal(ByteBuffer inBuffer, ByteBuffer outBuffer) throws IOException;

  /**
   * Generates a number of secure, random bytes suitable for cryptographic use.
   * This method needs to be thread-safe.
   *
   * @param bytes byte array to populate with random data
   */
  void generateSecureRandom(byte[] bytes);
}
