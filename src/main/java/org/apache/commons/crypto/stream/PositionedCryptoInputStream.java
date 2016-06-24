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
import org.apache.commons.crypto.utils.IOUtils;
import org.apache.commons.crypto.utils.Utils;
import static org.apache.commons.crypto.cipher.CipherTransformation.AES_CTR_NOPADDING;

/**
 * PositionedCryptoInputStream provides the capability to decrypt the stream
 * starting at random position as well as provides the foundation for positioned
 * read for decrypting. This needs a stream cipher mode such as AES CTR mode.
 */
public class PositionedCryptoInputStream extends CTRCryptoInputStream {

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
     * @param props The <code>Properties</code> class represents a set of
     *        properties.
     * @param in the input data.
     * @param key crypto key for the cipher.
     * @param iv Initialization vector for the cipher.
     * @param streamOffset the start offset in the data.
     * @throws IOException if an I/O error occurs.
     */
    public PositionedCryptoInputStream(Properties props, Input in, byte[] key,
            byte[] iv, long streamOffset) throws IOException {
        this(props, in, Utils.getCipherInstance(AES_CTR_NOPADDING, props),
                Utils.getBufferSize(props), key, iv, streamOffset);
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
    protected PositionedCryptoInputStream(Properties props, Input input, CryptoCipher cipher,
            int bufferSize, byte[] key, byte[] iv, long streamOffset)
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
    public int read(long position, byte[] buffer, int offset, int length)
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
    public void readFully(long position, byte[] buffer, int offset, int length)
            throws IOException {
        checkStream();
        IOUtils.readFully(input, position, buffer, offset, length);
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
    public void readFully(long position, byte[] buffer) throws IOException {
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
    protected void decrypt(long position, byte[] buffer, int offset, int length)
            throws IOException {
        ByteBuffer inBuffer = getBuffer();
        ByteBuffer outBuffer = getBuffer();
        CipherState state = null;
        try {
            state = getCipherState();
            byte[] iv = getInitIV().clone();
            resetCipher(state, position, iv);
            byte padding = getPadding(position);
            inBuffer.position(padding); // Set proper position for input data.

            int n = 0;
            while (n < length) {
                int toDecrypt = Math.min(length - n, inBuffer.remaining());
                inBuffer.put(buffer, offset + n, toDecrypt);

                // Do decryption
                decrypt(state, inBuffer, outBuffer, padding);

                outBuffer.get(buffer, offset + n, toDecrypt);
                n += toDecrypt;
                padding = postDecryption(state, inBuffer, position + n, iv);
            }
        } finally {
            returnBuffer(inBuffer);
            returnBuffer(outBuffer);
            returnCipherState(state);
        }
    }

    /**
     * Does the decryption using inBuffer as input and outBuffer as output. Upon
     * return, inBuffer is cleared; the decrypted data starts at
     * outBuffer.position() and ends at outBuffer.limit().
     *
     * @param state the CipherState instance.
     * @param inBuffer the input buffer.
     * @param outBuffer the output buffer.
     * @param padding the padding.
     * @throws IOException if an I/O error occurs.
     */
    private void decrypt(CipherState state, ByteBuffer inBuffer,
            ByteBuffer outBuffer, byte padding) throws IOException {
        Utils.checkState(inBuffer.position() >= padding);
        if (inBuffer.position() == padding) {
            // There is no real data in inBuffer.
            return;
        }
        inBuffer.flip();
        outBuffer.clear();
        decryptBuffer(state, inBuffer, outBuffer);
        inBuffer.clear();
        outBuffer.flip();
        if (padding > 0) {
            /*
             * The plain text and cipher text have a 1:1 mapping, they start at
             * the same position.
             */
            outBuffer.position(padding);
        }
    }

    /**
     * Does the decryption using inBuffer as input and outBuffer as output.
     *
     * @param state the CipherState instance.
     * @param inBuffer the input buffer.
     * @param outBuffer the output buffer.
     * @throws IOException if an I/O error occurs.
     */
    private void decryptBuffer(CipherState state, ByteBuffer inBuffer,
            ByteBuffer outBuffer) throws IOException {
        int inputSize = inBuffer.remaining();
        try {
            int n = state.getCipher().update(inBuffer, outBuffer);
            if (n < inputSize) {
                /**
                 * Typically code will not get here. CryptoCipher#update will
                 * consume all input data and put result in outBuffer.
                 * CryptoCipher#doFinal will reset the cipher context.
                 */
                state.getCipher().doFinal(inBuffer, outBuffer);
                state.reset(true);
            }
        } catch (ShortBufferException e) {
            throw new IOException(e);
        } catch (IllegalBlockSizeException e) {
            throw new IOException(e);
        } catch (BadPaddingException e) {
            throw new IOException(e);
        }
    }

    /**
     * This method is executed immediately after decryption. Check whether
     * cipher should be updated and recalculate padding if needed.
     *
     * @param state the CipherState instance.
     * @param inBuffer the input buffer.
     * @param position the offset from the start of the stream.
     * @param iv the iv.
     * @return the padding.
     * @throws IOException if an I/O error occurs.
     */
    private byte postDecryption(CipherState state, ByteBuffer inBuffer,
            long position, byte[] iv) throws IOException {
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
            inBuffer.position(padding);
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
    private void resetCipher(CipherState state, long position, byte[] iv)
            throws IOException {
        final long counter = getCounter(position);
        Utils.calculateIV(getInitIV(), counter, iv);
        try {
            state.getCipher().init(Cipher.DECRYPT_MODE, key,
                    new IvParameterSpec(iv));
        } catch (InvalidKeyException e) {
            throw new IOException(e);
        } catch (InvalidAlgorithmParameterException e) {
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
            CryptoCipher cipher;
            try {
                cipher = CryptoCipherFactory.getInstance(getCipher()
                        .getTransformation(), props);
            } catch (GeneralSecurityException e) {
                throw new IOException(e);
            }
            state = new CipherState(cipher);
        }

        return state;
    }

    /**
     * Returns CryptoCipher to pool.
     *
     * @param state the CipherState instance.
     */
    private void returnCipherState(CipherState state) {
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
    private void returnBuffer(ByteBuffer buf) {
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
            Utils.freeDirectBuffer(buf);
        }
    }

    private class CipherState {
        private CryptoCipher cipher;
        private boolean reset;

        /**
         * The constructor of {@Link CipherState}.
         *
         * @param cipher the CryptoCipher instance.
         */
        public CipherState(CryptoCipher cipher) {
            this.cipher = cipher;
            this.reset = false;
        }

        /**
         * Gets the CryptoCipher instance.
         *
         * @return the cipher.
         */
        public CryptoCipher getCipher() {
            return cipher;
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
        public void reset(boolean reset) {
            this.reset = reset;
        }
    }
}
