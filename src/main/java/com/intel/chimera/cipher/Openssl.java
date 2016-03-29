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
import java.security.NoSuchAlgorithmException;
import java.util.StringTokenizer;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.intel.chimera.utils.NativeCodeLoader;
import com.intel.chimera.utils.Utils;

/**
 * OpenSSL cryptographic wrapper using JNI.
 * Currently only AES-CTR is supported. It's flexible to add
 * other crypto algorithms/modes.
 */
public final class Openssl {
  private static final Log LOG = LogFactory.getLog(Openssl.class.getName());

  // Mode constant defined by Openssl JNI
  public static final int ENCRYPT_MODE = 1;
  public static final int DECRYPT_MODE = 0;

  /** Currently only support AES/CTR/NoPadding. */
  private static enum AlgorithmMode {
    AES_CTR,
    AES_CBC;

    static int get(String algorithm, String mode)
        throws NoSuchAlgorithmException {
      try {
        return AlgorithmMode.valueOf(algorithm + "_" + mode).ordinal();
      } catch (Exception e) {
        throw new NoSuchAlgorithmException("Doesn't support algorithm: " +
            algorithm + " and mode: " + mode);
      }
    }
  }

  private static enum Padding {
    NoPadding,
    PKCS5Padding;

    static int get(String padding) throws NoSuchPaddingException {
      try {
        return Padding.valueOf(padding).ordinal();
      } catch (Exception e) {
        throw new NoSuchPaddingException("Doesn't support padding: " + padding);
      }
    }
  }

  private long context = 0;
  private final int algorithm;
  private final int padding;

  private static final String loadingFailureReason;

  static {
    String loadingFailure = null;
    try {
      if (NativeCodeLoader.isNativeCodeLoaded()) {
        OpensslNative.initIDs();
      }
    } catch (Throwable t) {
      loadingFailure = t.getMessage();
      LOG.debug("Failed to load OpenSSL Cipher.", t);
    } finally {
      loadingFailureReason = loadingFailure;
    }
  }

  /**
   * Gets the failure reason when loading Openssl native.
   * @return the failure reason.
   */
  public static String getLoadingFailureReason() {
    return loadingFailureReason;
  }

  private Openssl(long context, int algorithm, int padding) {
    this.context = context;
    this.algorithm = algorithm;
    this.padding = padding;
  }

  /**
   * Return an <code>OpensslCipher<code> object that implements the specified
   * transformation.
   *
   * @param transformation the name of the transformation, e.g.,
   * AES/CTR/NoPadding.
   * @return OpensslCipher an <code>OpensslCipher<code> object
   * @throws NoSuchAlgorithmException if <code>transformation</code> is null,
   * empty, in an invalid format, or if Openssl doesn't implement the
   * specified algorithm.
   * @throws NoSuchPaddingException if <code>transformation</code> contains
   * a padding scheme that is not available.
   */
  public static final Openssl getInstance(String transformation)
      throws NoSuchAlgorithmException, NoSuchPaddingException {
    Transform transform = tokenizeTransformation(transformation);
    int algorithmMode = AlgorithmMode.get(transform.algorithm, transform.mode);
    int padding = Padding.get(transform.padding);
    long context = OpensslNative.initContext(algorithmMode, padding);
    return new Openssl(context, algorithmMode, padding);
  }

  /** Nested class for algorithm, mode and padding. */
  private static class Transform {
    final String algorithm;
    final String mode;
    final String padding;

    public Transform(String algorithm, String mode, String padding) {
      this.algorithm = algorithm;
      this.mode = mode;
      this.padding = padding;
    }
  }

  private static Transform tokenizeTransformation(String transformation)
      throws NoSuchAlgorithmException {
    if (transformation == null) {
      throw new NoSuchAlgorithmException("No transformation given.");
    }

    /*
     * Array containing the components of a Cipher transformation:
     *
     * index 0: algorithm (e.g., AES)
     * index 1: mode (e.g., CTR)
     * index 2: padding (e.g., NoPadding)
     */
    String[] parts = new String[3];
    int count = 0;
    StringTokenizer parser = new StringTokenizer(transformation, "/");
    while (parser.hasMoreTokens() && count < 3) {
      parts[count++] = parser.nextToken().trim();
    }
    if (count != 3 || parser.hasMoreTokens()) {
      throw new NoSuchAlgorithmException("Invalid transformation format: " +
          transformation);
    }
    return new Transform(parts[0], parts[1], parts[2]);
  }

  /**
   * Initialize this cipher with a key and IV.
   *
   * @param mode {@link #ENCRYPT_MODE} or {@link #DECRYPT_MODE}
   * @param key crypto key
   * @param iv crypto iv
   */
  public void init(int mode, byte[] key, byte[] iv) {
    context = OpensslNative.init(context, mode, algorithm, padding, key, iv);
  }

  /**
   * Continues a multiple-part encryption or decryption operation. The data
   * is encrypted or decrypted, depending on how this cipher was initialized.
   * <p/>
   *
   * All <code>input.remaining()</code> bytes starting at
   * <code>input.position()</code> are processed. The result is stored in
   * the output buffer.
   * <p/>
   *
   * Upon return, the input buffer's position will be equal to its limit;
   * its limit will not have changed. The output buffer's position will have
   * advanced by n, when n is the value returned by this method; the output
   * buffer's limit will not have changed.
   * <p/>
   *
   * If <code>output.remaining()</code> bytes are insufficient to hold the
   * result, a <code>ShortBufferException</code> is thrown.
   *
   * @param input the input ByteBuffer
   * @param output the output ByteBuffer
   * @return int number of bytes stored in <code>output</code>
   * @throws ShortBufferException if there is insufficient space in the
   * output buffer
   */
  public int update(ByteBuffer input, ByteBuffer output)
      throws ShortBufferException {
    checkState();
    Utils.checkArgument(input.isDirect() && output.isDirect(),
        "Direct buffers are required.");
    int len = OpensslNative.update(context, input, input.position(),
        input.remaining(), output, output.position(), output.remaining());
    input.position(input.limit());
    output.position(output.position() + len);
    return len;
  }

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
  public int update(byte[] input, int inputOffset, int inputLen,
      byte[] output, int outputOffset)
      throws ShortBufferException {
    checkState();
    return OpensslNative.updateByteArray(context, input, inputOffset, inputLen,
        output, outputOffset, output.length - outputOffset);
  }

  /**
   * Finishes a multiple-part operation. The data is encrypted or decrypted,
   * depending on how this cipher was initialized.
   * <p/>
   *
   * The result is stored in the output buffer. Upon return, the output buffer's
   * position will have advanced by n, where n is the value returned by this
   * method; the output buffer's limit will not have changed.
   * <p/>
   *
   * If <code>output.remaining()</code> bytes are insufficient to hold the result,
   * a <code>ShortBufferException</code> is thrown.
   * <p/>
   *
   * Upon finishing, this method resets this cipher object to the state it was
   * in when previously initialized. That is, the object is available to encrypt
   * or decrypt more data.
   * <p/>
   *
   * If any exception is thrown, this cipher object need to be reset before it
   * can be used again.
   *
   * @param output the output ByteBuffer
   * @return int number of bytes stored in <code>output</code>
   * @throws ShortBufferException
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   */
  public int doFinal(ByteBuffer output)
      throws ShortBufferException, IllegalBlockSizeException,
      BadPaddingException {
    checkState();
    Utils.checkArgument(output.isDirect(), "Direct buffer is required.");
    int len = OpensslNative.doFinal(context, output, output.position(), output.remaining());
    output.position(output.position() + len);
    return len;
  }

  /**
   * Encrypts or decrypts data in a single-part operation, or finishes a
   * multiple-part operation.
   *
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
  public int doFinal(byte[] output, int outputOffset)
      throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    checkState();
    return OpensslNative.doFinalByteArray(context,
        output, outputOffset, output.length - outputOffset);
  }

  /** Forcibly clean the context. */
  public void clean() {
    if (context != 0) {
      OpensslNative.clean(context);
      context = 0;
    }
  }

  /** Checks whether context is initialized. */
  private void checkState() {
    Utils.checkState(context != 0);
  }

  @Override
  protected void finalize() throws Throwable {
    clean();
  }

}
