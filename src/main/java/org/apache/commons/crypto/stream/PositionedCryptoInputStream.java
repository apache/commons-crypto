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
package org.apache.commons.crypto.stream;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Properties;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.stream.input.Input;
import org.apache.commons.crypto.utils.AES;
import org.apache.commons.crypto.utils.IoUtils;
import org.apache.commons.crypto.utils.Utils;
import org.apache.commons.io.IOUtils;

/**
 * PositionedCryptoInputStream provides the capability to decrypt the stream
 * starting at random position as well as provides the foundation for positioned
 * read for decrypting. This needs a stream cipher mode such as AES CTR mode.
 */
public class PositionedCryptoInputStream extends CtrCryptoInputStream {

    private static final class CipherState {

        private final CryptoCipher cryptoCipher;
        private boolean reset;

        /**
         * Constructs a new instance.
         *
         * @param cryptoCipher the CryptoCipher instance.
         */
        public CipherState(final CryptoCipher cryptoCipher) {
            this.cryptoCipher = cryptoCipher;
            this.reset = false;
        }

        /**
         * Gets the CryptoCipher instance.
         *
         * @return the cipher.
         */
        public CryptoCipher getCryptoCipher() {
            return cryptoCipher;
        }

        /**
         * Gets the reset.
         *
         * @return the value of reset.
         */
        public boolean isReset() {
            return reset;
        }

        /**
         * Sets the value of reset.
         *
         * @param reset the reset.
         */
        public void reset(final boolean reset) {
            this.reset = reset;
        }
    }

    /**
     * DirectBuffer pool
     */
    private final Queue<ByteBuffer> byteBufferPool = new ConcurrentLinkedQueue<>();

    /**
     * CryptoCipher pool
     */
    private final Queue<CipherState> cipherStatePool = new ConcurrentLinkedQueue<>();

    /**
     * properties for constructing a CryptoCipher
     */
    private final Properties properties;

    /**
     * Constructs a {@link PositionedCryptoInputStream}.
     *
     * @param properties The {@code Properties} class represents a set of
     *        properties.
     * @param in the input data.
     * @param key crypto key for the cipher.
     * @param iv Initialization vector for the cipher.
     * @param streamOffset the start offset in the data.
     * @throws IOException if an I/O error occurs.
     */
    @SuppressWarnings("resource") // The CryptoCipher returned by getCipherInstance() is closed by PositionedCryptoInputStream.
    public PositionedCryptoInputStream(final Properties properties, final Input in, final byte[] key,
            final byte[] iv, final long streamOffset) throws IOException {
        this(properties, in, Utils.getCipherInstance(AES.CTR_NO_PADDING, properties), getBufferSize(properties), key, iv, streamOffset);
    }

    /**
     * Constructs a {@link PositionedCryptoInputStream}.
     *
     * @param properties the properties of stream
     * @param input the input data.
     * @param cipher the CryptoCipher instance.
     * @param bufferSize the bufferSize.
     * @param key crypto key for the cipher.
     * @param iv Initialization vector for the cipher.
     * @param streamOffset the start offset in the data.
     * @throws IOException if an I/O error occurs.
     */
    protected PositionedCryptoInputStream(final Properties properties, final Input input, final CryptoCipher cipher,
            final int bufferSize, final byte[] key, final byte[] iv, final long streamOffset)
            throws IOException {
        super(input, cipher, bufferSize, key, iv, streamOffset);
        this.properties = properties;
    }

    /** Cleans direct buffer pool */
    private void cleanByteBufferPool() {
        ByteBuffer buf;
        while ((buf = byteBufferPool.poll()) != null) {
            buf.clear();
        }
    }

    /** Cleans direct buffer pool */
    private void cleanCipherStatePool() {
        CipherState cs;
        while ((cs = cipherStatePool.poll()) != null) {
            IOUtils.closeQuietly(cs.getCryptoCipher());
        }
    }

    /**
     * Overrides the {@link CryptoInputStream#close()}. Closes this input stream
     * and releases any system resources associated with the stream.
     *
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public void close() throws IOException {
        if (!isOpen()) {
            return;
        }

        cleanByteBufferPool();
        cleanCipherStatePool();
        super.close();
    }

    /**
     * Does the decryption using inBuffer as input and outBuffer as output. Upon
     * return, inBuffer is cleared; the decrypted data starts at
     * outBuffer.position() and ends at outBuffer.limit().
     *
     * @param state the CipherState instance.
     * @param inByteBuffer the input buffer.
     * @param outByteBuffer the output buffer.
     * @param padding the padding.
     * @throws IOException if an I/O error occurs.
     */
    private void decrypt(final CipherState state, final ByteBuffer inByteBuffer,
            final ByteBuffer outByteBuffer, final byte padding) throws IOException {
        Utils.checkState(inByteBuffer.position() >= padding);
        if (inByteBuffer.position() == padding) {
            // There is no real data in inBuffer.
            return;
        }
        inByteBuffer.flip();
        outByteBuffer.clear();
        decryptBuffer(state, inByteBuffer, outByteBuffer);
        inByteBuffer.clear();
        outByteBuffer.flip();
        if (padding > 0) {
            /*
             * The plain text and cipher text have a 1:1 mapping, they start at
             * the same position.
             */
            outByteBuffer.position(padding);
        }
    }

    /**
     * Decrypts length bytes in buffer starting at offset. Output is also put
     * into buffer starting at offset. It is thread-safe.
     *
     * @param buffer the buffer into which the data is read.
     * @param offset the start offset in the data.
     * @param position the offset from the start of the stream.
     * @param length the maximum number of bytes to read.
     * @throws IOException if an I/O error occurs.
     */
    protected void decrypt(final long position, final byte[] buffer, final int offset, final int length)
            throws IOException {
        final ByteBuffer inByteBuffer = getBuffer();
        final ByteBuffer outByteBuffer = getBuffer();
        CipherState state = null;
        try {
            state = getCipherState();
            final byte[] iv = getInitIV().clone();
            resetCipher(state, position, iv);
            byte padding = getPadding(position);
            inByteBuffer.position(padding); // Set proper position for input data.

            int n = 0;
            while (n < length) {
                final int toDecrypt = Math.min(length - n, inByteBuffer.remaining());
                inByteBuffer.put(buffer, offset + n, toDecrypt);

                // Do decryption
                decrypt(state, inByteBuffer, outByteBuffer, padding);

                outByteBuffer.get(buffer, offset + n, toDecrypt);
                n += toDecrypt;
                padding = postDecryption(state, inByteBuffer, position + n, iv);
            }
        } finally {
            returnToPool(inByteBuffer);
            returnToPool(outByteBuffer);
            returnToPool(state);
        }
    }

    /**
     * Does the decryption using inBuffer as input and outBuffer as output.
     *
     * @param state the CipherState instance.
     * @param inByteBuffer the input buffer.
     * @param outByteBuffer the output buffer.
     * @throws IOException if an I/O error occurs.
     */
    @SuppressWarnings("resource") // getCryptoCipher does not allocate
    private void decryptBuffer(final CipherState state, final ByteBuffer inByteBuffer,
            final ByteBuffer outByteBuffer) throws IOException {
        final int inputSize = inByteBuffer.remaining();
        try {
            final int n = state.getCryptoCipher().update(inByteBuffer, outByteBuffer);
            if (n < inputSize) {
                /**
                 * Typically code will not get here. CryptoCipher#update will
                 * consume all input data and put result in outBuffer.
                 * CryptoCipher#doFinal will reset the cipher context.
                 */
                state.getCryptoCipher().doFinal(inByteBuffer, outByteBuffer);
                state.reset(true);
            }
        } catch (final GeneralSecurityException e) {
            throw new IOException(e);
        }
    }

    /**
     * Gets direct buffer from pool. Caller MUST also call {@link #returnToPool(ByteBuffer)}.
     *
     * @return the buffer.
     * @see #returnToPool(ByteBuffer)
     */
    private ByteBuffer getBuffer() {
        final ByteBuffer buffer = byteBufferPool.poll();
        return buffer != null ? buffer : ByteBuffer.allocateDirect(getBufferSize());
    }

    /**
     * Gets CryptoCipher from pool. Caller MUST also call {@link #returnToPool(CipherState)}.
     *
     * @return the CipherState instance.
     * @throws IOException if an I/O error occurs.
     */
    @SuppressWarnings("resource") // Caller calls #returnToPool(CipherState)
    private CipherState getCipherState() throws IOException {
        final CipherState state = cipherStatePool.poll();
        return state != null ? state : new CipherState(Utils.getCipherInstance(AES.CTR_NO_PADDING, properties));
    }

    /**
     * This method is executed immediately after decryption. Check whether
     * cipher should be updated and recalculate padding if needed.
     *
     * @param state the CipherState instance.
     * @param inByteBuffer the input buffer.
     * @param position the offset from the start of the stream.
     * @param iv the iv.
     * @return the padding.
     */
    private byte postDecryption(final CipherState state, final ByteBuffer inByteBuffer,
            final long position, final byte[] iv) {
        byte padding = 0;
        if (state.isReset()) {
            /*
             * This code is generally not executed since the cipher usually
             * maintains cipher context (e.g. the counter) internally. However,
             * some implementations can't maintain context so a re-init is
             * necessary after each decryption call.
             */
            resetCipher(state, position, iv);
            padding = getPadding(position);
            inByteBuffer.position(padding);
        }
        return padding;
    }

    /**
     * Reads up to the specified number of bytes from a given position within a
     * stream and return the number of bytes read. This does not change the
     * current offset of the stream, and is thread-safe.
     *
     * @param buffer the buffer into which the data is read.
     * @param length the maximum number of bytes to read.
     * @param offset the start offset in the data.
     * @param position the offset from the start of the stream.
     * @throws IOException if an I/O error occurs.
     * @return int the total number of decrypted data bytes read into the
     *         buffer.
     */
    public int read(final long position, final byte[] buffer, final int offset, final int length)
            throws IOException {
        checkStream();
        final int n = input.read(position, buffer, offset, length);
        if (n > 0) {
            // This operation does not change the current offset of the file
            decrypt(position, buffer, offset, n);
        }
        return n;
    }

    /**
     * Reads the specified number of bytes from a given position within a
     * stream. This does not change the current offset of the stream and is
     * thread-safe.
     *
     * @param position the offset from the start of the stream.
     * @param buffer the buffer into which the data is read.
     * @throws IOException if an I/O error occurs.
     */
    public void readFully(final long position, final byte[] buffer) throws IOException {
        readFully(position, buffer, 0, buffer.length);
    }

    /**
     * Reads the specified number of bytes from a given position within a
     * stream. This does not change the current offset of the stream and is
     * thread-safe.
     *
     * @param buffer the buffer into which the data is read.
     * @param length the maximum number of bytes to read.
     * @param offset the start offset in the data.
     * @param position the offset from the start of the stream.
     * @throws IOException if an I/O error occurs.
     */
    public void readFully(final long position, final byte[] buffer, final int offset, final int length)
            throws IOException {
        checkStream();
        IoUtils.readFully(input, position, buffer, offset, length);
        if (length > 0) {
            // This operation does not change the current offset of the file
            decrypt(position, buffer, offset, length);
        }
    }

    /**
     * Calculates the counter and iv, reset the cipher.
     *
     * @param state the CipherState instance.
     * @param position the offset from the start of the stream.
     * @param iv the iv.
     */
    @SuppressWarnings("resource") // getCryptoCipher does not allocate
    private void resetCipher(final CipherState state, final long position, final byte[] iv) {
        final long counter = getCounter(position);
        calculateIV(getInitIV(), counter, iv);
        try {
            state.getCryptoCipher().init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        } catch (final GeneralSecurityException e) {
            // Ignore
        }
        state.reset(false);
    }

    /**
     * Returns direct buffer to pool.
     *
     * @param buf the buffer.
     */
    private void returnToPool(final ByteBuffer buf) {
        if (buf != null) {
            buf.clear();
            byteBufferPool.add(buf);
        }
    }

    /**
     * Returns CryptoCipher to pool.
     *
     * @param state the CipherState instance.
     */
    private void returnToPool(final CipherState state) {
        if (state != null) {
            cipherStatePool.add(state);
        }
    }
}
