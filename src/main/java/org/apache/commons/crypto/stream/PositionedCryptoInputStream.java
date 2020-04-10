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
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Properties;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.cipher.CryptoCipherFactory;
import org.apache.commons.crypto.stream.input.Input;
import org.apache.commons.crypto.utils.IoUtils;
import org.apache.commons.crypto.utils.Utils;

/**
 * PositionedCryptoInputStream provides the capability to decrypt the stream
 * starting at random position as well as provides the foundation for positioned
 * read for decrypting. This needs a stream cipher mode such as AES CTR mode.
 */
public class PositionedCryptoInputStream extends CtrCryptoInputStream {

    /**
     * DirectBuffer pool
     */
    private final Queue<ByteBuffer> bufferPool = new ConcurrentLinkedQueue<>();

    /**
     * CryptoCipher pool
     */
    private final Queue<CipherState> cipherPool = new ConcurrentLinkedQueue<>();

    /**
     * properties for constructing a CryptoCipher
     */
    private final Properties props;

    /**
     * Constructs a {@link PositionedCryptoInputStream}.
     *
     * @param props The {@code Properties} class represents a set of
     *        properties.
     * @param in the input data.
     * @param key crypto key for the cipher.
     * @param iv Initialization vector for the cipher.
     * @param streamOffset the start offset in the data.
     * @throws IOException if an I/O error occurs.
     */
    public PositionedCryptoInputStream(final Properties props, final Input in, final byte[] key,
            final byte[] iv, final long streamOffset) throws IOException {
        this(props, in, Utils.getCipherInstance("AES/CTR/NoPadding", props),
                CryptoInputStream.getBufferSize(props), key, iv, streamOffset);
    }

    /**
     * Constructs a {@link PositionedCryptoInputStream}.
     *
     * @param props the props of stream
     * @param input the input data.
     * @param cipher the CryptoCipher instance.
     * @param bufferSize the bufferSize.
     * @param key crypto key for the cipher.
     * @param iv Initialization vector for the cipher.
     * @param streamOffset the start offset in the data.
     * @throws IOException if an I/O error occurs.
     */
    protected PositionedCryptoInputStream(final Properties props, final Input input, final CryptoCipher cipher,
            final int bufferSize, final byte[] key, final byte[] iv, final long streamOffset)
            throws IOException {
        super(input, cipher, bufferSize, key, iv, streamOffset);
        this.props = props;
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
            returnBuffer(inByteBuffer);
            returnBuffer(outByteBuffer);
            returnCipherState(state);
        }
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
     * Does the decryption using inBuffer as input and outBuffer as output.
     *
     * @param state the CipherState instance.
     * @param inByteBuffer the input buffer.
     * @param outByteBuffer the output buffer.
     * @throws IOException if an I/O error occurs.
     */
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
        } catch (final ShortBufferException e) {
            throw new IOException(e);
        } catch (final IllegalBlockSizeException e) {
            throw new IOException(e);
        } catch (final BadPaddingException e) {
            throw new IOException(e);
        }
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
     * @throws IOException if an I/O error occurs.
     */
    private byte postDecryption(final CipherState state, final ByteBuffer inByteBuffer,
            final long position, final byte[] iv) throws IOException {
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
     * Calculates the counter and iv, reset the cipher.
     *
     * @param state the CipherState instance.
     * @param position the offset from the start of the stream.
     * @param iv the iv.
     * @throws IOException if an I/O error occurs.
     */
    private void resetCipher(final CipherState state, final long position, final byte[] iv)
            throws IOException {
        final long counter = getCounter(position);
        CtrCryptoInputStream.calculateIV(getInitIV(), counter, iv);
        try {
            state.getCryptoCipher().init(Cipher.DECRYPT_MODE, key,
                    new IvParameterSpec(iv));
        } catch (final InvalidKeyException e) {
            throw new IOException(e);
        } catch (final InvalidAlgorithmParameterException e) {
            throw new IOException(e);
        }
        state.reset(false);
    }

    /**
     * Gets CryptoCipher from pool.
     *
     * @return the CipherState instance.
     * @throws IOException if an I/O error occurs.
     */
    private CipherState getCipherState() throws IOException {
        CipherState state = cipherPool.poll();
        if (state == null) {
            CryptoCipher cryptoCipher;
            try {
                cryptoCipher = CryptoCipherFactory.getCryptoCipher("AES/CTR/NoPadding", props);
            } catch (final GeneralSecurityException e) {
                throw new IOException(e);
            }
            state = new CipherState(cryptoCipher);
        }

        return state;
    }

    /**
     * Returns CryptoCipher to pool.
     *
     * @param state the CipherState instance.
     */
    private void returnCipherState(final CipherState state) {
        if (state != null) {
            cipherPool.add(state);
        }
    }

    /**
     * Gets direct buffer from pool.
     *
     * @return the buffer.
     */
    private ByteBuffer getBuffer() {
        ByteBuffer buffer = bufferPool.poll();
        if (buffer == null) {
            buffer = ByteBuffer.allocateDirect(getBufferSize());
        }

        return buffer;
    }

    /**
     * Returns direct buffer to pool.
     *
     * @param buf the buffer.
     */
    private void returnBuffer(final ByteBuffer buf) {
        if (buf != null) {
            buf.clear();
            bufferPool.add(buf);
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

        cleanBufferPool();
        super.close();
    }

    /** Clean direct buffer pool */
    private void cleanBufferPool() {
        ByteBuffer buf;
        while ((buf = bufferPool.poll()) != null) {
            CryptoInputStream.freeDirectBuffer(buf);
        }
    }

    private class CipherState {
        private final CryptoCipher cryptoCipher;
        private boolean reset;

        /**
         * The constructor of {@link CipherState}.
         *
         * @param cipher the CryptoCipher instance.
         */
        public CipherState(final CryptoCipher cipher) {
            this.cryptoCipher = cipher;
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
}
