 /*
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
package org.apache.commons.crypto.jna;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.cipher.CryptoCipherFactory;
import org.apache.commons.crypto.utils.Transformation;

import com.sun.jna.NativeLong;
import com.sun.jna.ptr.PointerByReference;

/**
 * Implements the CryptoCipher using JNA into OpenSSL.
 */
final class OpenSslJnaCipher implements CryptoCipher {

    private static final int AES_128_ENCODED_KEYLEN = 16;
    private static final int AES_192_ENCODED_KEYLEN = 24;
    private static final int AES_256_ENCODED_KEYLEN = 32;

    /**
     * AlgorithmMode of JNA. Currently only support AES/CTR/NoPadding.
     */
    private enum AlgorithmMode {
        AES_CTR, AES_CBC;

        /**
         * Gets the AlgorithmMode instance.
         *
         * @param algorithm the algorithm name
         * @param mode      the mode name
         * @return the AlgorithmMode instance
         * @throws NoSuchAlgorithmException if the algorithm is not support
         */
        static AlgorithmMode get(final String algorithm, final String mode) throws NoSuchAlgorithmException {
            try {
                return AlgorithmMode.valueOf(algorithm + "_" + mode);
            } catch (final Exception e) {
                throw new NoSuchAlgorithmException("Algorithm not supported: " + algorithm + " and mode: " + mode);
            }
        }
    }
    private PointerByReference algo;
    private final PointerByReference context;
    private final AlgorithmMode algorithmMode;
    private final int padding;
    private final String transformation;

    private final int IV_LENGTH = 16;

    /**
     * Constructs a {@link CryptoCipher} using JNA into OpenSSL
     *
     * @param props          properties for OpenSSL cipher
     * @param transformation transformation for OpenSSL cipher
     * @throws GeneralSecurityException if OpenSSL cipher initialize failed
     */
    public OpenSslJnaCipher(final Properties props, final String transformation) // NOPMD
            throws GeneralSecurityException {
        if (!OpenSslJna.isEnabled()) {
            throw new GeneralSecurityException("Could not enable JNA access", OpenSslJna.initialisationError());
        }
        this.transformation = transformation;
        final Transformation transform = Transformation.parse(transformation);
        algorithmMode = AlgorithmMode.get(transform.getAlgorithm(), transform.getMode());

        if (algorithmMode != AlgorithmMode.AES_CBC && algorithmMode != AlgorithmMode.AES_CTR) {
            throw new GeneralSecurityException("Unknown algorithm " + transform.getAlgorithm() + "_" + transform.getMode());
        }

        padding = transform.getPadding().ordinal();
        context = OpenSslNativeJna.EVP_CIPHER_CTX_new();

    }

    /**
     * Closes the OpenSSL cipher. Clean the OpenSsl native context.
     */
    @Override
    public void close() {
        if (context != null) {
            OpenSslNativeJna.EVP_CIPHER_CTX_cleanup(context);
            // Freeing the context multiple times causes a JVM crash
            // A work-round is to only free it at finalize time
            // TODO is that sufficient?
            // OpenSslNativeJna.EVP_CIPHER_CTX_free(context);
        }
    }

    /**
     * Encrypts or decrypts data in a single-part operation, or finishes a
     * multiple-part operation.
     *
     * @param input        the input byte array
     * @param inputOffset  the offset in input where the input starts
     * @param inputLen     the input length
     * @param output       the byte array for the result
     * @param outputOffset the offset in output where the result is stored
     * @return the number of bytes stored in output
     * @throws ShortBufferException      if the given output byte array is too small
     *                                   to hold the result
     * @throws BadPaddingException       if this cipher is in decryption mode, and
     *                                   (un)padding has been requested, but the
     *                                   decrypted data is not bounded by the
     *                                   appropriate padding bytes
     * @throws IllegalBlockSizeException if this cipher is a block cipher, no
     *                                   padding has been requested (only in
     *                                   encryption mode), and the total input
     *                                   length of the data processed by this cipher
     *                                   is not a multiple of block size; or if this
     *                                   encryption algorithm is unable to process
     *                                   the input data provided.
     */
    @Override
    public int doFinal(final byte[] input, final int inputOffset, final int inputLen, final byte[] output,
            final int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        final ByteBuffer outputBuf = ByteBuffer.wrap(output, outputOffset, output.length - outputOffset);
        final ByteBuffer inputBuf = ByteBuffer.wrap(input, inputOffset, inputLen);
        return doFinal(inputBuf, outputBuf);
    }

    /**
     * Encrypts or decrypts data in a single-part operation, or finishes a
     * multiple-part operation. The data is encrypted or decrypted, depending on how
     * this cipher was initialized.
     *
     * @param inBuffer  the input ByteBuffer
     * @param outBuffer the output ByteBuffer
     * @return int number of bytes stored in {@code output}
     * @throws BadPaddingException       if this cipher is in decryption mode, and
     *                                   (un)padding has been requested, but the
     *                                   decrypted data is not bounded by the
     *                                   appropriate padding bytes
     * @throws IllegalBlockSizeException if this cipher is a block cipher, no
     *                                   padding has been requested (only in
     *                                   encryption mode), and the total input
     *                                   length of the data processed by this cipher
     *                                   is not a multiple of block size; or if this
     *                                   encryption algorithm is unable to process
     *                                   the input data provided.
     * @throws ShortBufferException      if the given output buffer is too small to
     *                                   hold the result
     */
    @Override
    public int doFinal(final ByteBuffer inBuffer, final ByteBuffer outBuffer)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        final int uptLen = update(inBuffer, outBuffer);
        final int[] outlen = new int[1];
        throwOnError(OpenSslNativeJna.EVP_CipherFinal_ex(context, outBuffer, outlen));
        final int len = uptLen + outlen[0];
        outBuffer.position(outBuffer.position() + outlen[0]);
        return len;
    }

    @Override
    protected void finalize() throws Throwable {
        OpenSslNativeJna.EVP_CIPHER_CTX_free(context);
        super.finalize();
    }

    @Override
    public String getAlgorithm() {
        return transformation;
    }

    @Override
    public int getBlockSize() {
        return CryptoCipherFactory.AES_BLOCK_SIZE;
    }

    /**
     * Initializes the cipher with mode, key and iv.
     *
     * @param mode   {@link Cipher#ENCRYPT_MODE} or {@link Cipher#DECRYPT_MODE}
     * @param key    crypto key for the cipher
     * @param params the algorithm parameters
     * @throws InvalidKeyException                If key length is invalid
     * @throws InvalidAlgorithmParameterException if IV length is wrong
     */
    @Override
    public void init(final int mode, final Key key, final AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(params, "params");
        final int cipherMode = mode == Cipher.ENCRYPT_MODE ? OpenSslNativeJna.OOSL_JNA_ENCRYPT_MODE : OpenSslNativeJna.OOSL_JNA_DECRYPT_MODE;
        if (!(params instanceof IvParameterSpec)) {
            // other AlgorithmParameterSpec such as GCMParameterSpec is not
            // supported now.
            throw new InvalidAlgorithmParameterException("Illegal parameters");
        }
        final byte[] iv = ((IvParameterSpec) params).getIV();

        if ((algorithmMode == AlgorithmMode.AES_CBC || algorithmMode == AlgorithmMode.AES_CTR) && iv.length != IV_LENGTH) {
            throw new InvalidAlgorithmParameterException("Wrong IV length: must be 16 bytes long");
        }
        final int keyEncodedLength = key.getEncoded().length;

        if (algorithmMode == AlgorithmMode.AES_CBC) {
            switch (keyEncodedLength) {
            case AES_128_ENCODED_KEYLEN:
                algo = OpenSslNativeJna.EVP_aes_128_cbc();
                break;
            case AES_192_ENCODED_KEYLEN:
                algo = OpenSslNativeJna.EVP_aes_192_cbc();
                break;
            case AES_256_ENCODED_KEYLEN:
                algo = OpenSslNativeJna.EVP_aes_256_cbc();
                break;
            default:
                throw new InvalidKeyException("keysize unsupported (" + keyEncodedLength + ")");
            }

        } else {
            switch (keyEncodedLength) {
            case AES_128_ENCODED_KEYLEN:
                algo = OpenSslNativeJna.EVP_aes_128_ctr();
                break;
            case AES_192_ENCODED_KEYLEN:
                algo = OpenSslNativeJna.EVP_aes_192_ctr();
                break;
            case AES_256_ENCODED_KEYLEN:
                algo = OpenSslNativeJna.EVP_aes_256_ctr();
                break;
            default:
                throw new InvalidKeyException("keysize unsupported (" + keyEncodedLength + ")");
            }
        }

        throwOnError(OpenSslNativeJna.EVP_CipherInit_ex(context, algo, null, key.getEncoded(), iv, cipherMode));
        throwOnError(OpenSslNativeJna.EVP_CIPHER_CTX_set_padding(context, padding));
    }

    /**
     * @param retVal the result value of error.
     */
    private void throwOnError(final int retVal) {
        if (retVal != 1) {
            final NativeLong err = OpenSslNativeJna.ERR_peek_error();
            final String errdesc = OpenSslNativeJna.ERR_error_string(err, null);

            if (context != null) {
                OpenSslNativeJna.EVP_CIPHER_CTX_cleanup(context);
            }
            throw new IllegalStateException(
                    "return code " + retVal + " from OpenSSL. Err code is " + err + ": " + errdesc);
        }
    }

    /**
     * Continues a multiple-part encryption/decryption operation. The data is
     * encrypted or decrypted, depending on how this cipher was initialized.
     *
     * @param input        the input byte array
     * @param inputOffset  the offset in input where the input starts
     * @param inputLen     the input length
     * @param output       the byte array for the result
     * @param outputOffset the offset in output where the result is stored
     * @return the number of bytes stored in output
     * @throws ShortBufferException if there is insufficient space in the output
     *                              byte array
     */
    @Override
    public int update(final byte[] input, final int inputOffset, final int inputLen, final byte[] output,
            final int outputOffset) throws ShortBufferException {
        final ByteBuffer outputBuf = ByteBuffer.wrap(output, outputOffset, output.length - outputOffset);
        final ByteBuffer inputBuf = ByteBuffer.wrap(input, inputOffset, inputLen);
        return update(inputBuf, outputBuf);
    }

    /**
     * Continues a multiple-part encryption/decryption operation. The data is
     * encrypted or decrypted, depending on how this cipher was initialized.
     *
     * @param inBuffer  the input ByteBuffer
     * @param outBuffer the output ByteBuffer
     * @return int number of bytes stored in {@code output}
     * @throws ShortBufferException if there is insufficient space in the output
     *                              buffer
     */
    @Override
    public int update(final ByteBuffer inBuffer, final ByteBuffer outBuffer) throws ShortBufferException {
        final int[] outlen = new int[1];
        throwOnError(OpenSslNativeJna.EVP_CipherUpdate(context, outBuffer, outlen, inBuffer, inBuffer.remaining()));
        final int len = outlen[0];
        inBuffer.position(inBuffer.limit());
        outBuffer.position(outBuffer.position() + len);
        return len;
    }

    /**
     * Continues a multi-part update of the Additional Authentication Data (AAD).
     * <p>
     * Calls to this method provide AAD to the opensslEngine when operating in modes
     * such as AEAD (GCM). If this opensslEngine is operating in either GCM mode,
     * all AAD must be supplied before beginning operations on the ciphertext (via
     * the {@code update} and {@code doFinal} methods).
     * </p>
     *
     * @param aad the buffer containing the Additional Authentication Data
     *
     * @throws IllegalArgumentException      if the {@code aad} byte array is {@code null}
     * @throws IllegalStateException         if this opensslEngine is in a wrong
     *                                       state (e.g., has not been initialized),
     *                                       does not accept AAD, or if operating in
     *                                       either GCM mode and one of the
     *                                       {@code update} methods has already been
     *                                       called for the active
     *                                       encryption/decryption operation
     * @throws UnsupportedOperationException if the implementation
     *                                       {@code opensslEngine} doesn't support
     *                                       this operation.
     */
    @Override
    public void updateAAD(final byte[] aad)
            throws IllegalArgumentException, IllegalStateException, UnsupportedOperationException {
        // TODO: implement GCM mode using Jna
        throw new UnsupportedOperationException("This is unsupported in Jna Cipher");
    }

    /**
     * Continues a multi-part update of the Additional Authentication Data (AAD).
     * <p>
     * Calls to this method provide AAD to the opensslEngine when operating in modes
     * such as AEAD (GCM). If this opensslEngine is operating in either GCM mode,
     * all AAD must be supplied before beginning operations on the ciphertext (via
     * the {@code update} and {@code doFinal} methods).
     * </p>
     *
     * @param aad the buffer containing the Additional Authentication Data
     *
     * @throws IllegalArgumentException      if the {@code aad} byte array is {@code null}
     * @throws IllegalStateException         if this opensslEngine is in a wrong
     *                                       state (e.g., has not been initialized),
     *                                       does not accept AAD, or if operating in
     *                                       either GCM mode and one of the
     *                                       {@code update} methods has already been
     *                                       called for the active
     *                                       encryption/decryption operation
     * @throws UnsupportedOperationException if the implementation
     *                                       {@code opensslEngine} doesn't support
     *                                       this operation.
     */
    @Override
    public void updateAAD(final ByteBuffer aad)
            throws IllegalArgumentException, IllegalStateException, UnsupportedOperationException {
        // TODO: implement GCM mode using Jna
        throw new UnsupportedOperationException("This is unsupported in Jna Cipher");
    }
}
