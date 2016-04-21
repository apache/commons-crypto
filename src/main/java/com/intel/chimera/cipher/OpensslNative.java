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

import java.nio.ByteBuffer;

/**
 * JNI interface of {@link Openssl} implementation. The native method in this class is
 * defined in OpensslNative.h(genereted by javah).
 */
public class OpensslNative {

  private OpensslNative() {}

  /**
   * Declares a native method to initialize JNI field and method IDs.
   */
  public native static void initIDs();

  /**
   * Declares a native method to initialize the cipher context.
   *
   * @param algorithm The algorithm name of cipher
   * @param padding The padding name of cipher
   * @return the context address of cipher
   */
  public native static long initContext(int algorithm, int padding);

  /**
   * Declares a native method to initialize the cipher context.
   *
   * @return the context address of cipher
   */
  public native static long init(long context, int mode, int alg, int padding,
      byte[] key, byte[] iv);

  /**
   * Continues a multiple-part encryption/decryption operation. The data
   * is encrypted or decrypted, depending on how this cipher was initialized.
   *
   * @param context The cipher context address
   * @param input The input byte buffer
   * @param inputOffset The offset in input where the input starts
   * @param inputLength The input length
   * @param output The byte buffer for the result
   * @param outputOffset The offset in output where the result is stored
   * @param maxOutputLength The maximum length for output
   * @return The number of bytes stored in output
   */
  public native static int update(long context, ByteBuffer input,
      int inputOffset, int inputLength, ByteBuffer output, int outputOffset,
      int maxOutputLength);

  /**
   * Continues a multiple-part encryption/decryption operation. The data
   * is encrypted or decrypted, depending on how this cipher was initialized.
   *
   * @param context The cipher context address
   * @param input The input byte array
   * @param inputOffset  The offset in input where the input starts
   * @param inputLength The input length
   * @param output The byte array for the result
   * @param outputOffset The offset in output where the result is stored
   * @param maxOutputLength The maximum length for output
   * @return The number of bytes stored in output
   */
  public native static int updateByteArray(long context, byte[] input,
      int inputOffset, int inputLength, byte[] output, int outputOffset,
      int maxOutputLength);

  /**
   * Finishes a multiple-part operation. The data is encrypted or decrypted,
   * depending on how this cipher was initialized.
   *
   * @param context The cipher context address
   * @param output The byte buffer for the result
   * @param offset The offset in output where the result is stored
   * @param maxOutputLength The maximum length for output
   * @return The number of bytes stored in output
   */
  public native static int doFinal(long context, ByteBuffer output, int offset,
      int maxOutputLength);

  /**
   * Finishes a multiple-part operation. The data is encrypted or decrypted,
   * depending on how this cipher was initialized.
   *
   * @param context The cipher context address
   * @param output The byte array for the result
   * @param offset The offset in output where the result is stored
   * @param maxOutputLength The maximum length for output
   * @return The number of bytes stored in output
   */
  public native static int doFinalByteArray(long context, byte[] output, int offset,
      int maxOutputLength);

  /**
   * Cleans the context at native.
   *
   * @param context The cipher context address
   */
  public native static void clean(long context);
}
