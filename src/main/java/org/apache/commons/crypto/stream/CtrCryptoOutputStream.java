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
package org.apache.commons.crypto.stream;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.WritableByteChannel;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.stream.output.ChannelOutput;
import org.apache.commons.crypto.stream.output.Output;
import org.apache.commons.crypto.stream.output.StreamOutput;
import org.apache.commons.crypto.utils.Utils;

/**
 * <p>
 * CtrCryptoOutputStream encrypts data. It is not thread-safe. AES CTR mode is
 * required in order to ensure that the plain text and cipher text have a 1:1
 * mapping. The encryption is buffer based. The key points of the encryption are
 * (1) calculating counter and (2) padding through stream position.
 * </p>
 * <p>
 * counter = base + pos/(algorithm blocksize); padding = pos%(algorithm
 * blocksize);
 * </p>
 * <p>
 * The underlying stream offset is maintained as state.
 * </p>
 * <p>
 * This class should only be used with blocking sinks. Using this class to wrap
 * a non-blocking sink may lead to high CPU usage.
 * </p>
 */
public class CtrCryptoOutputStream extends CryptoOutputStream {
    /**
     * Underlying stream offset.
     */
    private long streamOffset = 0;

    /**
     * The initial IV.
     */
    private final byte[] initIV;

    /**
     * Initialization vector for the cipher.
     */
    private final byte[] iv;

    /**
     * Padding = pos%(algorithm blocksize); Padding is put into
     * {@link #inBuffer} before any other data goes in. The purpose of padding
     * is to put input data at proper position.
     */
    private byte padding;

    /**
     * Flag to mark whether the cipher has been reset
     */
    private boolean cipherReset = false;

    /**
     * Constructs a {@link CtrCryptoOutputStream}.
     *
     * @param props The {@code Properties} class represents a set of
     *        properties.
     * @param out the output stream.
     * @param key crypto key for the cipher.
     * @param iv Initialization vector for the cipher.
     * @throws IOException if an I/O error occurs.
     */
    public CtrCryptoOutputStream(final Properties props, final OutputStream out,
            final byte[] key, final byte[] iv) throws IOException {
        this(props, out, key, iv, 0);
    }

    /**
     * Constructs a {@link CtrCryptoOutputStream}.
     *
     * @param props The {@code Properties} class represents a set of
     *        properties.
     * @param out the WritableByteChannel instance.
     * @param key crypto key for the cipher.
     * @param iv Initialization vector for the cipher.
     * @throws IOException if an I/O error occurs.
     */
    public CtrCryptoOutputStream(final Properties props, final WritableByteChannel out,
            final byte[] key, final byte[] iv) throws IOException {
        this(props, out, key, iv, 0);
    }

    /**
     * Constructs a {@link CtrCryptoOutputStream}.
     *
     * @param out the output stream.
     * @param cipher the CryptoCipher instance.
     * @param bufferSize the bufferSize.
     * @param key crypto key for the cipher.
     * @param iv Initialization vector for the cipher.
     * @throws IOException if an I/O error occurs.
     */
    protected CtrCryptoOutputStream(final OutputStream out, final CryptoCipher cipher,
            final int bufferSize, final byte[] key, final byte[] iv) throws IOException {
        this(out, cipher, bufferSize, key, iv, 0);
    }

    /**
     * Constructs a {@link CtrCryptoOutputStream}.
     *
     * @param channel the WritableByteChannel instance.
     * @param cipher the CryptoCipher instance.
     * @param bufferSize the bufferSize.
     * @param key crypto key for the cipher.
     * @param iv Initialization vector for the cipher.
     * @throws IOException if an I/O error occurs.
     */
    protected CtrCryptoOutputStream(final WritableByteChannel channel,
            final CryptoCipher cipher, final int bufferSize, final byte[] key, final byte[] iv)
            throws IOException {
        this(channel, cipher, bufferSize, key, iv, 0);
    }

    /**
     * Constructs a {@link CtrCryptoOutputStream}.
     *
     * @param output the Output instance.
     * @param cipher the CryptoCipher instance.
     * @param bufferSize the bufferSize.
     * @param key crypto key for the cipher.
     * @param iv Initialization vector for the cipher.
     * @throws IOException if an I/O error occurs.
     */
    protected CtrCryptoOutputStream(final Output output, final CryptoCipher cipher,
            final int bufferSize, final byte[] key, final byte[] iv) throws IOException {
        this(output, cipher, bufferSize, key, iv, 0);
    }

    /**
     * Constructs a {@link CtrCryptoOutputStream}.
     *
     * @param props The {@code Properties} class represents a set of
     *        properties.
     * @param out the output stream.
     * @param key crypto key for the cipher.
     * @param iv Initialization vector for the cipher.
     * @param streamOffset the start offset in the data.
     * @throws IOException if an I/O error occurs.
     */
    public CtrCryptoOutputStream(final Properties props, final OutputStream out,
            final byte[] key, final byte[] iv, final long streamOffset) throws IOException {
        this(out, Utils.getCipherInstance(
                "AES/CTR/NoPadding", props),
                CryptoInputStream.getBufferSize(props), key, iv, streamOffset);
    }

    /**
     * Constructs a {@link CtrCryptoOutputStream}.
     *
     * @param props The {@code Properties} class represents a set of
     *        properties.
     * @param out the WritableByteChannel instance.
     * @param key crypto key for the cipher.
     * @param iv Initialization vector for the cipher.
     * @param streamOffset the start offset in the data.
     * @throws IOException if an I/O error occurs.
     */
    public CtrCryptoOutputStream(final Properties props, final WritableByteChannel out,
            final byte[] key, final byte[] iv, final long streamOffset) throws IOException {
        this(out, Utils.getCipherInstance(
                "AES/CTR/NoPadding", props),
                CryptoInputStream.getBufferSize(props), key, iv, streamOffset);
    }

    /**
     * Constructs a {@link CtrCryptoOutputStream}.
     *
     * @param out the output stream.
     * @param cipher the CryptoCipher instance.
     * @param bufferSize the bufferSize.
     * @param key crypto key for the cipher.
     * @param iv Initialization vector for the cipher.
     * @param streamOffset the start offset in the data.
     * @throws IOException if an I/O error occurs.
     */
    protected CtrCryptoOutputStream(final OutputStream out, final CryptoCipher cipher,
            final int bufferSize, final byte[] key, final byte[] iv, final long streamOffset)
            throws IOException {
        this(new StreamOutput(out, bufferSize), cipher, bufferSize, key, iv,
                streamOffset);
    }

    /**
     * Constructs a {@link CtrCryptoOutputStream}.
     *
     * @param channel the WritableByteChannel instance.
     * @param cipher the CryptoCipher instance.
     * @param bufferSize the bufferSize.
     * @param key crypto key for the cipher.
     * @param iv Initialization vector for the cipher.
     * @param streamOffset the start offset in the data.
     * @throws IOException if an I/O error occurs.
     */
    protected CtrCryptoOutputStream(final WritableByteChannel channel,
            final CryptoCipher cipher, final int bufferSize, final byte[] key, final byte[] iv,
            final long streamOffset) throws IOException {
        this(new ChannelOutput(channel), cipher, bufferSize, key, iv,
                streamOffset);
    }

    /**
     * Constructs a {@link CtrCryptoOutputStream}.
     *
     * @param output the output stream.
     * @param cipher the CryptoCipher instance.
     * @param bufferSize the bufferSize.
     * @param key crypto key for the cipher.
     * @param iv Initialization vector for the cipher.
     * @param streamOffset the start offset in the data.
     * @throws IOException if an I/O error occurs.
     */
    protected CtrCryptoOutputStream(final Output output, final CryptoCipher cipher,
            final int bufferSize, final byte[] key, final byte[] iv, final long streamOffset)
            throws IOException {
        super(output, cipher, bufferSize, new SecretKeySpec(key, "AES"),
                new IvParameterSpec(iv));

        CryptoInputStream.checkStreamCipher(cipher);
        this.streamOffset = streamOffset;
        this.initIV = iv.clone();
        this.iv = iv.clone();

        resetCipher();
    }

    /**
     * Does the encryption, input is {@link #inBuffer} and output is
     * {@link #outBuffer}.
     *
     * @throws IOException if an I/O error occurs.
     */
    @Override
    protected void encrypt() throws IOException {
        Utils.checkState(inBuffer.position() >= padding);
        if (inBuffer.position() == padding) {
            // There is no real data in the inBuffer.
            return;
        }

        inBuffer.flip();
        outBuffer.clear();
        encryptBuffer(outBuffer);
        inBuffer.clear();
        outBuffer.flip();

        if (padding > 0) {
            /*
             * The plain text and cipher text have a 1:1 mapping, they start at
             * the same position.
             */
            outBuffer.position(padding);
            padding = 0;
        }

        final int len = output.write(outBuffer);
        streamOffset += len;
        if (cipherReset) {
            /*
             * This code is generally not executed since the encryptor usually
             * maintains encryption context (e.g. the counter) internally.
             * However, some implementations can't maintain context so a re-init
             * is necessary after each encryption call.
             */
            resetCipher();
        }
    }

    /**
     * Does final encryption of the last data.
     *
     * @throws IOException if an I/O error occurs.
     */
    @Override
    protected void encryptFinal() throws IOException {
        // The same as the normal encryption for Counter mode
        encrypt();
    }

    /**
     * Overrides the {@link CryptoOutputStream#initCipher()}. Initializes the
     * cipher.
     */
    @Override
    protected void initCipher() {
        // Do nothing for initCipher
        // Will reset the cipher considering the stream offset
    }

    /**
     * Resets the {@link #cipher}: calculate counter and {@link #padding}.
     *
     * @throws IOException if an I/O error occurs.
     */
    private void resetCipher() throws IOException {
        final long counter = streamOffset
                / cipher.getBlockSize();
        padding = (byte) (streamOffset % cipher.getBlockSize());
        inBuffer.position(padding); // Set proper position for input data.

        CtrCryptoInputStream.calculateIV(initIV, counter, iv);
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        } catch (final InvalidKeyException e) {
            throw new IOException(e);
        } catch (final InvalidAlgorithmParameterException e) {
            throw new IOException(e);
        }
        cipherReset = false;
    }

    /**
     * Does the encryption if the ByteBuffer data.
     *
     * @param out the output ByteBuffer.
     * @throws IOException if an I/O error occurs.
     */
    private void encryptBuffer(final ByteBuffer out) throws IOException {
        final int inputSize = inBuffer.remaining();
        try {
            final int n = cipher.update(inBuffer, out);
            if (n < inputSize) {
                /**
                 * Typically code will not get here. CryptoCipher#update will
                 * consume all input data and put result in outBuffer.
                 * CryptoCipher#doFinal will reset the cipher context.
                 */
                cipher.doFinal(inBuffer, out);
                cipherReset = true;
            }
        } catch (final ShortBufferException e) {
            throw new IOException(e);
        } catch (final BadPaddingException e) {
            throw new IOException(e);
        } catch (final IllegalBlockSizeException e) {
            throw new IOException(e);
        }
    }

    /**
     * Get the underlying stream offset
     *
     * @return the underlying stream offset
     */
    protected long getStreamOffset() {
        return streamOffset;
    }

    /**
     * Set the underlying stream offset
     *
     * @param streamOffset the underlying stream offset
     */
    protected void setStreamOffset(final long streamOffset) {
        this.streamOffset = streamOffset;
    }
}
