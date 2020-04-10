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
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
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
import org.apache.commons.crypto.cipher.CryptoCipherFactory;
import org.apache.commons.crypto.stream.input.ChannelInput;
import org.apache.commons.crypto.stream.input.Input;
import org.apache.commons.crypto.stream.input.StreamInput;
import org.apache.commons.crypto.utils.Utils;

/**
 * <p>
 * CtrCryptoInputStream decrypts data. AES CTR mode is required in order to
 * ensure that the plain text and cipher text have a 1:1 mapping. CTR crypto
 * stream has stream characteristic which is useful for implement features like
 * random seek. The decryption is buffer based. The key points of the decryption
 * are (1) calculating the counter and (2) padding through stream position:
 * </p>
 * <p>
 * counter = base + pos/(algorithm blocksize); padding = pos%(algorithm
 * blocksize);
 * </p>
 * The underlying stream offset is maintained as state. It is not thread-safe.
 */
public class CtrCryptoInputStream extends CryptoInputStream {
    /**
     * Underlying stream offset
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
     * is to put the input data at proper position.
     */
    private byte padding;

    /**
     * Flag to mark whether the cipher has been reset
     */
    private boolean cipherReset = false;

    /**
     * Constructs a {@link CtrCryptoInputStream}.
     *
     * @param props The {@code Properties} class represents a set of
     *        properties.
     * @param in the input stream.
     * @param key crypto key for the cipher.
     * @param iv Initialization vector for the cipher.
     * @throws IOException if an I/O error occurs.
     */
    public CtrCryptoInputStream(final Properties props, final InputStream in, final byte[] key,
            final byte[] iv) throws IOException {
        this(props, in, key, iv, 0);
    }

    /**
     * Constructs a {@link CtrCryptoInputStream}.
     *
     * @param props The {@code Properties} class represents a set of
     *        properties.
     * @param in the ReadableByteChannel instance.
     * @param key crypto key for the cipher.
     * @param iv Initialization vector for the cipher.
     * @throws IOException if an I/O error occurs.
     */
    public CtrCryptoInputStream(final Properties props, final ReadableByteChannel in,
            final byte[] key, final byte[] iv) throws IOException {
        this(props, in, key, iv, 0);
    }

    /**
     * Constructs a {@link CtrCryptoInputStream}.
     *
     * @param in the input stream.
     * @param cipher the CryptoCipher instance.
     * @param bufferSize the bufferSize.
     * @param key crypto key for the cipher.
     * @param iv Initialization vector for the cipher.
     * @throws IOException if an I/O error occurs.
     */
    protected CtrCryptoInputStream(final InputStream in, final CryptoCipher cipher,
            final int bufferSize, final byte[] key, final byte[] iv) throws IOException {
        this(in, cipher, bufferSize, key, iv, 0);
    }

    /**
     * Constructs a {@link CtrCryptoInputStream}.
     *
     * @param in the ReadableByteChannel instance.
     * @param cipher the cipher instance.
     * @param bufferSize the bufferSize.
     * @param key crypto key for the cipher.
     * @param iv Initialization vector for the cipher.
     * @throws IOException if an I/O error occurs.
     */
    protected CtrCryptoInputStream(final ReadableByteChannel in, final CryptoCipher cipher,
            final int bufferSize, final byte[] key, final byte[] iv) throws IOException {
        this(in, cipher, bufferSize, key, iv, 0);
    }

    /**
     * Constructs a {@link CtrCryptoInputStream}.
     *
     * @param input the input data.
     * @param cipher the CryptoCipher instance.
     * @param bufferSize the bufferSize.
     * @param key crypto key for the cipher.
     * @param iv Initialization vector for the cipher.
     * @throws IOException if an I/O error occurs.
     */
    protected CtrCryptoInputStream(final Input input, final CryptoCipher cipher,
            final int bufferSize, final byte[] key, final byte[] iv) throws IOException {
        this(input, cipher, bufferSize, key, iv, 0);
    }

    /**
     * Constructs a {@link CtrCryptoInputStream}.
     *
     * @param props The {@code Properties} class represents a set of
     *        properties.
     * @param in the InputStream instance.
     * @param key crypto key for the cipher.
     * @param iv Initialization vector for the cipher.
     * @param streamOffset the start offset in the stream.
     * @throws IOException if an I/O error occurs.
     */
    public CtrCryptoInputStream(final Properties props, final InputStream in, final byte[] key,
            final byte[] iv, final long streamOffset) throws IOException {
        this(in, Utils.getCipherInstance(
                "AES/CTR/NoPadding", props),
                CryptoInputStream.getBufferSize(props), key, iv, streamOffset);
    }

    /**
     * Constructs a {@link CtrCryptoInputStream}.
     *
     * @param props The {@code Properties} class represents a set of
     *        properties.
     * @param in the ReadableByteChannel instance.
     * @param key crypto key for the cipher.
     * @param iv Initialization vector for the cipher.
     * @param streamOffset the start offset in the stream.
     * @throws IOException if an I/O error occurs.
     */
    public CtrCryptoInputStream(final Properties props, final ReadableByteChannel in,
            final byte[] key, final byte[] iv, final long streamOffset) throws IOException {
        this(in, Utils.getCipherInstance(
                "AES/CTR/NoPadding", props),
                CryptoInputStream.getBufferSize(props), key, iv, streamOffset);
    }

    /**
     * Constructs a {@link CtrCryptoInputStream}.
     *
     * @param in the InputStream instance.
     * @param cipher the CryptoCipher instance.
     * @param bufferSize the bufferSize.
     * @param key crypto key for the cipher.
     * @param iv Initialization vector for the cipher.
     * @param streamOffset the start offset in the stream.
     * @throws IOException if an I/O error occurs.
     */
    protected CtrCryptoInputStream(final InputStream in, final CryptoCipher cipher,
            final int bufferSize, final byte[] key, final byte[] iv, final long streamOffset)
            throws IOException {
        this(new StreamInput(in, bufferSize), cipher, bufferSize, key, iv,
                streamOffset);
    }

    /**
     * Constructs a {@link CtrCryptoInputStream}.
     *
     * @param in the ReadableByteChannel instance.
     * @param cipher the CryptoCipher instance.
     * @param bufferSize the bufferSize.
     * @param key crypto key for the cipher.
     * @param iv Initialization vector for the cipher.
     * @param streamOffset the start offset in the stream.
     * @throws IOException if an I/O error occurs.
     */
    protected CtrCryptoInputStream(final ReadableByteChannel in, final CryptoCipher cipher,
            final int bufferSize, final byte[] key, final byte[] iv, final long streamOffset)
            throws IOException {
        this(new ChannelInput(in), cipher, bufferSize, key, iv, streamOffset);
    }

    /**
     * Constructs a {@link CtrCryptoInputStream}.
     *
     * @param input the input data.
     * @param cipher the CryptoCipher instance.
     * @param bufferSize the bufferSize.
     * @param key crypto key for the cipher.
     * @param iv Initialization vector for the cipher.
     * @param streamOffset the start offset in the stream.
     * @throws IOException if an I/O error occurs.
     */
    protected CtrCryptoInputStream(final Input input, final CryptoCipher cipher,
            final int bufferSize, final byte[] key, final byte[] iv, final long streamOffset)
            throws IOException {
        super(input, cipher, bufferSize, new SecretKeySpec(key, "AES"),
                new IvParameterSpec(iv));

        this.initIV = iv.clone();
        this.iv = iv.clone();

        CryptoInputStream.checkStreamCipher(cipher);

        resetStreamOffset(streamOffset);
    }

    /**
     * Overrides the {@link CryptoInputStream#skip(long)}. Skips over and
     * discards {@code n} bytes of data from this input stream.
     *
     * @param n the number of bytes to be skipped.
     * @return the actual number of bytes skipped.
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public long skip(long n) throws IOException {
        Utils.checkArgument(n >= 0, "Negative skip length.");
        checkStream();

        if (n == 0) {
            return 0;
        } else if (n <= outBuffer.remaining()) {
            final int pos = outBuffer.position() + (int) n;
            outBuffer.position(pos);
            return n;
        } else {
            /*
             * Subtract outBuffer.remaining() to see how many bytes we need to
             * skip in the underlying stream. Add outBuffer.remaining() to the
             * actual number of skipped bytes in the underlying stream to get
             * the number of skipped bytes from the user's point of view.
             */
            n -= outBuffer.remaining();
            long skipped = input.skip(n);
            if (skipped < 0) {
                skipped = 0;
            }
            final long pos = streamOffset + skipped;
            skipped += outBuffer.remaining();
            resetStreamOffset(pos);
            return skipped;
        }
    }

    /**
     * Overrides the {@link CtrCryptoInputStream#read(ByteBuffer)}. Reads a
     * sequence of bytes from this channel into the given buffer.
     *
     * @param buf The buffer into which bytes are to be transferred.
     * @return The number of bytes read, possibly zero, or <tt>-1</tt> if the
     *         channel has reached end-of-stream.
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public int read(final ByteBuffer buf) throws IOException {
        checkStream();
        int unread = outBuffer.remaining();
        if (unread <= 0) { // Fill the unread decrypted data buffer firstly
            final int n = input.read(inBuffer);
            if (n <= 0) {
                return n;
            }

            streamOffset += n; // Read n bytes
            if (buf.isDirect() && buf.remaining() >= inBuffer.position()
                    && padding == 0) {
                // Use buf as the output buffer directly
                decryptInPlace(buf);
                padding = postDecryption(streamOffset);
                return n;
            }
            // Use outBuffer as the output buffer
            decrypt();
            padding = postDecryption(streamOffset);
        }

        // Copy decrypted data from outBuffer to buf
        unread = outBuffer.remaining();
        final int toRead = buf.remaining();
        if (toRead <= unread) {
            final int limit = outBuffer.limit();
            outBuffer.limit(outBuffer.position() + toRead);
            buf.put(outBuffer);
            outBuffer.limit(limit);
            return toRead;
        }
        buf.put(outBuffer);
        return unread;
    }

    /**
     * Seeks the stream to a specific position relative to start of the under
     * layer stream.
     *
     * @param position the given position in the data.
     * @throws IOException if an I/O error occurs.
     */
    public void seek(final long position) throws IOException {
        Utils.checkArgument(position >= 0, "Cannot seek to negative offset.");
        checkStream();
        /*
         * If data of target pos in the underlying stream has already been read
         * and decrypted in outBuffer, we just need to re-position outBuffer.
         */
        if (position >= getStreamPosition() && position <= getStreamOffset()) {
            final int forward = (int) (position - getStreamPosition());
            if (forward > 0) {
                outBuffer.position(outBuffer.position() + forward);
            }
        } else {
            input.seek(position);
            resetStreamOffset(position);
        }
    }

    /**
     * Gets the offset of the stream.
     *
     * @return the stream offset.
     */
    protected long getStreamOffset() {
        return streamOffset;
    }

    /**
     * Sets the offset of stream.
     *
     * @param streamOffset the stream offset.
     */
    protected void setStreamOffset(final long streamOffset) {
        this.streamOffset = streamOffset;
    }

    /**
     * Gets the position of the stream.
     *
     * @return the position of the stream.
     */
    protected long getStreamPosition() {
        return streamOffset - outBuffer.remaining();
    }

    /**
     * Decrypts more data by reading the under layer stream. The decrypted data
     * will be put in the output buffer.
     *
     * @return The number of decrypted data. -1 if end of the decrypted stream.
     * @throws IOException if an I/O error occurs.
     */
    @Override
    protected int decryptMore() throws IOException {
        final int n = input.read(inBuffer);
        if (n <= 0) {
            return n;
        }

        streamOffset += n; // Read n bytes
        decrypt();
        padding = postDecryption(streamOffset);
        return outBuffer.remaining();
    }

    /**
     * Does the decryption using inBuffer as input and outBuffer as output. Upon
     * return, inBuffer is cleared; the decrypted data starts at
     * outBuffer.position() and ends at outBuffer.limit().
     *
     * @throws IOException if an I/O error occurs.
     */
    @Override
    protected void decrypt() throws IOException {
        Utils.checkState(inBuffer.position() >= padding);
        if (inBuffer.position() == padding) {
            // There is no real data in inBuffer.
            return;
        }

        inBuffer.flip();
        outBuffer.clear();
        decryptBuffer(outBuffer);
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
     * Does the decryption using inBuffer as input and buf as output. Upon
     * return, inBuffer is cleared; the buf's position will be equal to
     * <i>p</i>&nbsp;<tt>+</tt>&nbsp;<i>n</i> where <i>p</i> is the position
     * before decryption, <i>n</i> is the number of bytes decrypted. The buf's
     * limit will not have changed.
     *
     * @param buf The buffer into which bytes are to be transferred.
     * @throws IOException if an I/O error occurs.
     */
    protected void decryptInPlace(final ByteBuffer buf) throws IOException {
        Utils.checkState(inBuffer.position() >= padding);
        Utils.checkState(buf.isDirect());
        Utils.checkState(buf.remaining() >= inBuffer.position());
        Utils.checkState(padding == 0);

        if (inBuffer.position() == padding) {
            // There is no real data in inBuffer.
            return;
        }
        inBuffer.flip();
        decryptBuffer(buf);
        inBuffer.clear();
    }

    /**
     * Decrypts all data in buf: total n bytes from given start position. Output
     * is also buf and same start position. buf.position() and buf.limit()
     * should be unchanged after decryption.
     *
     * @param buf The buffer into which bytes are to be transferred.
     * @param offset the start offset in the data.
     * @param len the maximum number of decrypted data bytes to read.
     * @throws IOException if an I/O error occurs.
     */
    protected void decrypt(final ByteBuffer buf, final int offset, final int len)
            throws IOException {
        final int pos = buf.position();
        final int limit = buf.limit();
        int n = 0;
        while (n < len) {
            buf.position(offset + n);
            buf.limit(offset + n + Math.min(len - n, inBuffer.remaining()));
            inBuffer.put(buf);
            // Do decryption
            try {
                decrypt();
                buf.position(offset + n);
                buf.limit(limit);
                n += outBuffer.remaining();
                buf.put(outBuffer);
            } finally {
                padding = postDecryption(streamOffset - (len - n));
            }
        }
        buf.position(pos);
    }

    /**
     * This method is executed immediately after decryption. Checks whether
     * cipher should be updated and recalculate padding if needed.
     *
     * @param position the given position in the data..
     * @return the byte.
     * @throws IOException if an I/O error occurs.
     */
    protected byte postDecryption(final long position) throws IOException {
        byte padding = 0;
        if (cipherReset) {
            /*
             * This code is generally not executed since the cipher usually
             * maintains cipher context (e.g. the counter) internally. However,
             * some implementations can't maintain context so a re-init is
             * necessary after each decryption call.
             */
            resetCipher(position);
            padding = getPadding(position);
            inBuffer.position(padding);
        }
        return padding;
    }

    /**
     * Gets the initialization vector.
     *
     * @return the initIV.
     */
    protected byte[] getInitIV() {
        return initIV;
    }

    /**
     * Gets the counter for input stream position.
     *
     * @param position the given position in the data.
     * @return the counter for input stream position.
     */
    protected long getCounter(final long position) {
        return position / cipher.getBlockSize();
    }

    /**
     * Gets the padding for input stream position.
     *
     * @param position the given position in the data.
     * @return the padding for input stream position.
     */
    protected byte getPadding(final long position) {
        return (byte) (position % cipher.getBlockSize());
    }

    /**
     * Overrides the {@link CtrCryptoInputStream#initCipher()}. Initializes the
     * cipher.
     */
    @Override
    protected void initCipher() {
        // Do nothing for initCipher
        // Will reset the cipher when reset the stream offset
    }

    /**
     * Calculates the counter and iv, resets the cipher.
     *
     * @param position the given position in the data.
     * @throws IOException if an I/O error occurs.
     */
    protected void resetCipher(final long position) throws IOException {
        final long counter = getCounter(position);
        CtrCryptoInputStream.calculateIV(initIV, counter, iv);
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        } catch (final InvalidKeyException e) {
            throw new IOException(e);
        } catch (final InvalidAlgorithmParameterException e) {
            throw new IOException(e);
        }
        cipherReset = false;
    }

    /**
     * Resets the underlying stream offset; clear {@link #inBuffer} and
     * {@link #outBuffer}. This Typically happens during {@link #skip(long)}.
     *
     * @param offset the offset of the stream.
     * @throws IOException if an I/O error occurs.
     */
    protected void resetStreamOffset(final long offset) throws IOException {
        streamOffset = offset;
        inBuffer.clear();
        outBuffer.clear();
        outBuffer.limit(0);
        resetCipher(offset);
        padding = getPadding(offset);
        inBuffer.position(padding); // Set proper position for input data.
    }

    /**
     * Does the decryption using out as output.
     *
     * @param out the output ByteBuffer.
     * @throws IOException if an I/O error occurs.
     */
    protected void decryptBuffer(final ByteBuffer out) throws IOException {
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
        } catch (final IllegalBlockSizeException e) {
            throw new IOException(e);
        } catch (final BadPaddingException e) {
            throw new IOException(e);
        }
    }

    /**
     * <p>
     * This method is only for Counter (CTR) mode. Generally the CryptoCipher
     * calculates the IV and maintain encryption context internally.For example
     * a Cipher will maintain its encryption context internally when we do
     * encryption/decryption using the CryptoCipher#update interface.
     * </p>
     * <p>
     * Encryption/Decryption is not always on the entire file. For example, in
     * Hadoop, a node may only decrypt a portion of a file (i.e. a split). In
     * these situations, the counter is derived from the file position.
     * </p>
     * The IV can be calculated by combining the initial IV and the counter with
     * a lossless operation (concatenation, addition, or XOR).
     *
     * @see <a
     *      href="http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_.28CTR.29">
     *      http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_.28CTR.29</a>
     *
     * @param initIV initial IV
     * @param counter counter for input stream position
     * @param IV the IV for input stream position
     */
    static void calculateIV(final byte[] initIV, long counter, final byte[] IV) {
        Utils.checkArgument(initIV.length == CryptoCipherFactory.AES_BLOCK_SIZE);
        Utils.checkArgument(IV.length == CryptoCipherFactory.AES_BLOCK_SIZE);

        int i = IV.length; // IV length
        int j = 0; // counter bytes index
        int sum = 0;
        while (i-- > 0) {
            // (sum >>> Byte.SIZE) is the carry for addition
            sum = (initIV[i] & 0xff) + (sum >>> Byte.SIZE); // NOPMD
            if (j++ < 8) { // Big-endian, and long is 8 bytes length
                sum += (byte) counter & 0xff;
                counter >>>= 8;
            }
            IV[i] = (byte) sum;
        }
    }
}
