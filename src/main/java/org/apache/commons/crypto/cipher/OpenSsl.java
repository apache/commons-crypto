 /*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.commons.crypto.cipher;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import org.apache.commons.crypto.Crypto;
import org.apache.commons.crypto.utils.Transformation;
import org.apache.commons.crypto.utils.Utils;

/**
 * OpenSSL cryptographic wrapper using JNI. Currently only AES-CTR is supported.
 * It's flexible to add other crypto algorithms/modes.
 */
final class OpenSsl {

    /** Currently only support AES/CTR/NoPadding. */
    private enum AlgorithmMode {
        AES_CTR, AES_CBC, AES_GCM, SM4_CTR, SM4_CBC;

        /**
         * Gets the mode.
         *
         * @param algorithm the algorithm.
         * @param mode the mode.
         * @return the Algorithm mode.
         * @throws NoSuchAlgorithmException if the algorithm is not available.
         */
        static int get(final String algorithm, final String mode) throws NoSuchAlgorithmException {
            try {
                return AlgorithmMode.valueOf(algorithm + "_" + mode).ordinal();
            } catch (final Exception e) {
                throw new NoSuchAlgorithmException("Algorithm not supported: " + algorithm + " and mode: " + mode);
            }
        }
    }
    // Mode constant defined by OpenSsl JNI
    public static final int ENCRYPT_MODE = 1;

    public static final int DECRYPT_MODE = 0;

    private static final Throwable loadingFailureReason;

    static {
        Throwable loadingFailure = null;
        try {
            if (Crypto.isNativeCodeLoaded()) {
                OpenSslNative.initIDs();
            } else {
                loadingFailure = Crypto.getLoadingError();
            }
        } catch (final Exception | UnsatisfiedLinkError t) {
            loadingFailure = t;
        } finally {
            loadingFailureReason = loadingFailure;
        }
    }

    /**
     * Gets an {@code OpenSslCipher} that implements the specified
     * transformation.
     *
     * @param transformation the name of the transformation, e.g.,
     *        AES/CTR/NoPadding.
     * @return OpenSslCipher an {@code OpenSslCipher} object
     * @throws NoSuchAlgorithmException if {@code transformation} is {@code null},
     *         empty, in an invalid format, or if OpenSsl doesn't implement the
     *         specified algorithm.
     * @throws NoSuchPaddingException if {@code transformation} contains a
     *         padding scheme that is not available.
     * @throws IllegalStateException if native code cannot be initialized
     */
    public static OpenSsl getInstance(final String transformation)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
        if (loadingFailureReason != null) {
            throw new IllegalStateException(loadingFailureReason);
        }
        final Transformation transform = Transformation.parse(transformation);
        final int algorithmMode = AlgorithmMode.get(transform.getAlgorithm(), transform.getMode());
        final int padding = transform.getPadding().ordinal();
        final long context = OpenSslNative.initContext(algorithmMode, padding);
        return new OpenSsl(context, algorithmMode, padding);
    }

    /**
     * Gets the failure reason when loading OpenSsl native.
     *
     * @return the failure reason; {@code null} if it was loaded and initialized successfully
     */
    public static Throwable getLoadingFailureReason() {
        return loadingFailureReason;
    }

    private final AbstractOpenSslFeedbackCipher opensslBlockCipher;

    /**
     * Constructs a {@link OpenSsl} instance based on context, algorithm and padding.
     *
     * @param context the context.
     * @param algorithm the algorithm.
     * @param padding the padding.
     */
    private OpenSsl(final long context, final int algorithm, final int padding) {
        if (algorithm == AlgorithmMode.AES_GCM.ordinal()) {
            opensslBlockCipher = new OpenSslGaloisCounterMode(context, algorithm, padding);
        } else {
            opensslBlockCipher = new OpenSslCommonMode(context, algorithm, padding);
        }
    }

    /** Forcibly clean the context. */
    public void clean() {
        if (opensslBlockCipher != null) {
            opensslBlockCipher.clean();
        }
    }

    /**
     * Finalizes to encrypt or decrypt data in a single-part operation, or finishes a
     * multiple-part operation.
     *
     * @param input the input byte array
     * @param inputOffset the offset in input where the input starts
     * @param inputLen the input length
     * @param output the byte array for the result
     * @param outputOffset the offset in output where the result is stored
     * @return the number of bytes stored in output
     * @throws ShortBufferException if the given output byte array is too small
     *         to hold the result
     * @throws BadPaddingException if this cipher is in decryption mode, and
     *         (un)padding has been requested, but the decrypted data is not
     *         bounded by the appropriate padding bytes
     * @throws IllegalBlockSizeException if this cipher is a block cipher, no
     *         padding has been requested (only in encryption mode), and the
     *         total input length of the data processed by this cipher is not a
     *         multiple of block size; or if this encryption algorithm is unable
     *         to process the input data provided.
     */
    public int doFinal(final byte[] input, final int inputOffset, final int inputLen, final byte[] output, final int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        return opensslBlockCipher.doFinal(input, inputOffset, inputLen, output, outputOffset);
    }

    /**
     * Finishes a multiple-part operation. The data is encrypted or decrypted,
     * depending on how this cipher was initialized.
     *
     * <p>
     * The result is stored in the output buffer. Upon return, the output
     * buffer's position will have advanced by n, where n is the value returned
     * by this method; the output buffer's limit will not have changed.
     * </p>
     *
     * <p>
     * If {@code output.remaining()} bytes are insufficient to hold the
     * result, a {@code ShortBufferException} is thrown.
     * </p>
     *
     * <p>
     * Upon finishing, this method resets this cipher object to the state it was
     * in when previously initialized. That is, the object is available to
     * encrypt or decrypt more data.
     * </p>
     *
     * If any exception is thrown, this cipher object need to be reset before it
     * can be used again.
     *
     * @param input the input ByteBuffer
     * @param output the output ByteBuffer
     * @return int number of bytes stored in {@code output}
     * @throws ShortBufferException if the given output byte array is too small
     *         to hold the result.
     * @throws IllegalBlockSizeException if this cipher is a block cipher, no
     *         padding has been requested (only in encryption mode), and the
     *         total input length of the data processed by this cipher is not a
     *         multiple of block size; or if this encryption algorithm is unable
     *         to process the input data provided.
     * @throws BadPaddingException if this cipher is in decryption mode, and
     *         (un)padding has been requested, but the decrypted data is not
     *         bounded by the appropriate padding bytes
     */
    public int doFinal(final ByteBuffer input, final ByteBuffer output) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        Utils.checkArgument(output.isDirect(), "Direct buffer is required.");

        return opensslBlockCipher.doFinal(input, output);
    }

    @Override
    protected void finalize() throws Throwable {
        clean();
    }

    /**
     * Initializes this cipher with a key and IV.
     *
     * @param mode {@link #ENCRYPT_MODE} or {@link #DECRYPT_MODE}
     * @param key crypto key
     * @param params the algorithm parameters
     * @throws InvalidAlgorithmParameterException if IV length is wrong
     */
    public void init(final int mode, final byte[] key, final AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
        opensslBlockCipher.init(mode, key, params);
    }

    /**
     * Updates a multiple-part encryption/decryption operation. The data is
     * encrypted or decrypted, depending on how this cipher was initialized.
     *
     * @param input the input byte array
     * @param inputOffset the offset in input where the input starts
     * @param inputLen the input length
     * @param output the byte array for the result
     * @param outputOffset the offset in output where the result is stored
     * @return the number of bytes stored in output
     * @throws ShortBufferException if there is insufficient space in the output
     *         byte array
     */
    public int update(final byte[] input, final int inputOffset, final int inputLen,
            final byte[] output, final int outputOffset) throws ShortBufferException {
        return opensslBlockCipher.update(input, inputOffset, inputLen, output, outputOffset);
    }

    /**
     * Updates a multiple-part encryption or decryption operation. The data is
     * encrypted or decrypted, depending on how this cipher was initialized.
     *
     * <p>
     * All {@code input.remaining()} bytes starting at
     * {@code input.position()} are processed. The result is stored in the
     * output buffer.
     * </p>
     *
     * <p>
     * Upon return, the input buffer's position will be equal to its limit; its
     * limit will not have changed. The output buffer's position will have
     * advanced by n, when n is the value returned by this method; the output
     * buffer's limit will not have changed.
     * </p>
     *
     * If {@code output.remaining()} bytes are insufficient to hold the
     * result, a {@code ShortBufferException} is thrown.
     *
     * @param input the input ByteBuffer
     * @param output the output ByteBuffer
     * @return int number of bytes stored in {@code output}
     * @throws ShortBufferException if there is insufficient space in the output
     *         buffer
     */
    public int update(final ByteBuffer input, final ByteBuffer output) throws ShortBufferException {
        Utils.checkArgument(input.isDirect() && output.isDirect(), "Direct buffers are required.");
        return opensslBlockCipher.update(input, output);
    }

    /**
     * Continues a multi-part update of the Additional Authentication
     * Data (AAD).
     * <p>
     * Calls to this method provide AAD to the cipher when operating in
     * modes such as AEAD (GCM).  If this cipher is operating in
     * either GCM mode, all AAD must be supplied before beginning
     * operations on the ciphertext (via the {@code update} and
     * {@code doFinal} methods).
     * </p>
     *
     * @param aad the buffer containing the Additional Authentication Data
     */
    public void updateAAD(final byte[] aad) {
        this.opensslBlockCipher.updateAAD(aad);
    }

}
