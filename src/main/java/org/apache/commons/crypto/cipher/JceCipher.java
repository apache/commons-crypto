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
package org.apache.commons.crypto.cipher;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

import org.apache.commons.crypto.utils.Utils;

/**
 * Implements the {@link CryptoCipher} using JCE provider.
 */
public class JceCipher implements CryptoCipher {
    private final Properties props;
    private final CipherTransformation transformation;
    private final Cipher cipher;

    /**
     * Constructs a {@link CryptoCipher} based on JCE Cipher {@link Cipher}.
     *
     * @param props properties for JCE cipher
     * @param transformation transformation for JCE cipher
     * @throws GeneralSecurityException if JCE cipher initialize failed
     */
    public JceCipher(Properties props, CipherTransformation transformation)
            throws GeneralSecurityException {
        this.props = props;
        this.transformation = transformation;

        String provider = Utils.getJCEProvider(props);
        if (provider == null || provider.isEmpty()) {
            cipher = Cipher.getInstance(transformation.getName());
        } else {
            cipher = Cipher.getInstance(transformation.getName(), provider);
        }
    }

    /**
     * Gets the CipherTransformation for the jce cipher.
     *
     * @return the CipherTransformation for this cipher
     */
    @Override
    public CipherTransformation getTransformation() {
        return transformation;
    }

    /**
     * Gets the properties for the jce cipher.
     *
     * @return the properties for this cipher.
     */
    @Override
    public Properties getProperties() {
        return props;
    }

    /**
     * Initializes the cipher with mode, key and iv.
     *
     * @param mode {@link #ENCRYPT_MODE} or {@link #DECRYPT_MODE}
     * @param key crypto key for the cipher
     * @param params the algorithm parameters
     * @throws InvalidAlgorithmParameterException if the given algorithm
     *         parameters are inappropriate for this cipher, or this cipher
     *         requires algorithm parameters and <code>params</code> is null, or
     *         the given algorithm parameters imply a cryptographic strength
     *         that would exceed the legal limits (as determined from the
     *         configured jurisdiction policy files).
     */
    @Override
    public void init(int mode, Key key, AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        Utils.checkNotNull(key);
        Utils.checkNotNull(params);

        int cipherMode = Cipher.DECRYPT_MODE;
        if (mode == ENCRYPT_MODE) {
            cipherMode = Cipher.ENCRYPT_MODE;
        }
        cipher.init(cipherMode, key, params);
    }

    /**
     * Continues a multiple-part encryption/decryption operation. The data is
     * encrypted or decrypted, depending on how this cipher was initialized.
     *
     * @param inBuffer the input ByteBuffer
     * @param outBuffer the output ByteBuffer
     * @return int number of bytes stored in <code>output</code>
     * @throws ShortBufferException if there is insufficient space in the output
     *         buffer
     */
    @Override
    public int update(ByteBuffer inBuffer, ByteBuffer outBuffer)
            throws ShortBufferException {
        return cipher.update(inBuffer, outBuffer);
    }

    /**
     * Continues a multiple-part encryption/decryption operation. The data is
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
    @Override
    public int update(byte[] input, int inputOffset, int inputLen,
            byte[] output, int outputOffset) throws ShortBufferException {
        return cipher
                .update(input, inputOffset, inputLen, output, outputOffset);
    }

    /**
     * Encrypts or decrypts data in a single-part operation, or finishes a
     * multiple-part operation. The data is encrypted or decrypted, depending on
     * how this cipher was initialized.
     *
     * @param inBuffer the input ByteBuffer
     * @param outBuffer the output ByteBuffer
     * @return int number of bytes stored in <code>output</code>
     * @throws BadPaddingException if this cipher is in decryption mode, and
     *         (un)padding has been requested, but the decrypted data is not
     *         bounded by the appropriate padding bytes
     * @throws IllegalBlockSizeException if this cipher is a block cipher, no
     *         padding has been requested (only in encryption mode), and the
     *         total input length of the data processed by this cipher is not a
     *         multiple of block size; or if this encryption algorithm is unable
     *         to process the input data provided.
     * @throws ShortBufferException if the given output buffer is too small to
     *         hold the result
     */
    @Override
    public int doFinal(ByteBuffer inBuffer, ByteBuffer outBuffer)
            throws ShortBufferException, IllegalBlockSizeException,
            BadPaddingException {
        return cipher.doFinal(inBuffer, outBuffer);
    }

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
    @Override
    public int doFinal(byte[] input, int inputOffset, int inputLen,
            byte[] output, int outputOffset) throws ShortBufferException,
            IllegalBlockSizeException, BadPaddingException {
        return cipher.doFinal(input, inputOffset, inputLen, output,
                outputOffset);
    }

    /**
     * Closes Jce cipher.
     */
    @Override
    public void close() {
        // Do nothing
    }
}
