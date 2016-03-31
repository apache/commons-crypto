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
package com.intel.chimera.cipher;

import java.io.Closeable;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

/**
 * The interface of cryptographic cipher for encryption and decryption.
 */
public interface Cipher extends Closeable {

  /**
   * A constant representing encrypt mode.  The mode constant to be used
   * when calling init method of the Cipher.
   */
  int ENCRYPT_MODE = 1;

  /**
   * A constant representing decrypt mode.  The mode constant to be used 
   * when calling init method of the Cipher.
   */
  int DECRYPT_MODE = 0;

  /**
   * Gets the CipherTransformation for this cipher.
   *
   * @return the CipherTransformation for this cipher.
   */
  CipherTransformation getTransformation();

  /**
   * Gets the properties for this cipher.
   * 
   * @return the properties for this cipher.
   */
  Properties getProperties();

  /**
   * Initializes the cipher with mode, key and iv.
   * 
   * @param mode {@link #ENCRYPT_MODE} or {@link #DECRYPT_MODE}
   * @param key crypto key for the cipher
   * @param iv Initialization vector for the cipher
   * @throws InvalidKeyException if the given key is inappropriate for
   * initializing this cipher, or its keysize exceeds the maximum allowable
   * keysize (as determined from the configured jurisdiction policy files).
   * @throws InvalidAlgorithmParameterException if the given algorithm
   * parameters are inappropriate for this cipher, or this cipher requires
   * algorithm parameters and <code>params</code> is null, or the given
   * algorithm parameters imply a cryptographic strength that would exceed
   * the legal limits (as determined from the configured jurisdiction
   * policy files).
   */
  void init(int mode, byte[] key, byte[] iv)
      throws InvalidKeyException, InvalidAlgorithmParameterException;

  /**
   * Continues a multiple-part encryption/decryption operation. The data
   * is encrypted or decrypted, depending on how this cipher was initialized.
   * 
   * @param inBuffer the input ByteBuffer
   * @param outBuffer the output ByteBuffer
   * @return int number of bytes stored in <code>output</code>
   * @throws ShortBufferException if there is insufficient space
   * in the output buffer
   */
  int update(ByteBuffer inBuffer, ByteBuffer outBuffer)
      throws ShortBufferException;

  /**
   * Continues a multiple-part encryption/decryption operation. The data
   * is encrypted or decrypted, depending on how this cipher was initialized.
   *
   * @param input the input byte array
   * @param inputOffset the offset in input where the input starts
   * @param inputLen the input length
   * @param output the byte array for the result
   * @param outputOffset the offset in output where the result is stored
   * @return the number of bytes stored in output
   * @throws ShortBufferException if there is insufficient space in the output byte array
   */
  int update(byte[] input, int inputOffset, int inputLen,
      byte[] output, int outputOffset)
      throws ShortBufferException;

  /**
   * Encrypts or decrypts data in a single-part operation, or finishes a
   * multiple-part operation.
   * 
   * @param inBuffer the input ByteBuffer
   * @param outBuffer the output ByteBuffer
   * @return int number of bytes stored in <code>output</code>
   * @throws BadPaddingException if this cipher is in decryption mode,
   * and (un)padding has been requested, but the decrypted data is not
   * bounded by the appropriate padding bytes
   * @throws IllegalBlockSizeException if this cipher is a block cipher,
   * no padding has been requested (only in encryption mode), and the total
   * input length of the data processed by this cipher is not a multiple of
   * block size; or if this encryption algorithm is unable to
   * process the input data provided.
   * @throws ShortBufferException if the given output buffer is too small
   * to hold the result
   */
  int doFinal(ByteBuffer inBuffer, ByteBuffer outBuffer)
      throws ShortBufferException, IllegalBlockSizeException,
      BadPaddingException;

  /**
   * Encrypts or decrypts data in a single-part operation, or finishes a
   * multiple-part operation.
   *
   * @param input the input byte array
   * @param inputOffset the offset in input where the input starts
   * @param inputLen the input length
   * @param output the byte array for the result
   * @param outputOffset the offset in output where the result is stored
   * @return the number of bytes stored in output
   * @throws ShortBufferException if the given output byte array is too small
   * to hold the result
   * @throws BadPaddingException if this cipher is in decryption mode,
   * and (un)padding has been requested, but the decrypted data is not
   * bounded by the appropriate padding bytes
   * @throws IllegalBlockSizeException if this cipher is a block cipher,
   * no padding has been requested (only in encryption mode), and the total
   * input length of the data processed by this cipher is not a multiple of
   * block size; or if this encryption algorithm is unable to
   * process the input data provided.
   */
  int doFinal(byte[] input, int inputOffset, int inputLen,
      byte[] output, int outputOffset)
      throws ShortBufferException, IllegalBlockSizeException, BadPaddingException;
}
