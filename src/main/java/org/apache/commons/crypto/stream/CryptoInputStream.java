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
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.crypto.Crypto;
import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.stream.input.ChannelInput;
import org.apache.commons.crypto.stream.input.Input;
import org.apache.commons.crypto.stream.input.StreamInput;
import org.apache.commons.crypto.utils.Utils;

/**
 * CryptoInputStream reads input data and decrypts data in stream manner. It
 * supports any mode of operations such as AES CBC/CTR/GCM mode in concept.It is
 * not thread-safe.
 *
 */

public class CryptoInputStream extends InputStream implements
        ReadableByteChannel {
    private final byte[] oneByteBuf = new byte[1];

    /**
     * The configuration key of the buffer size for stream.
     */
    public static final String STREAM_BUFFER_SIZE_KEY = Crypto.CONF_PREFIX
            + "stream.buffer.size";

    /** The CryptoCipher instance. */
    final CryptoCipher cipher; // package protected for access by crypto classes; do not expose futher

    /** The buffer size. */
    private final int bufferSize;

    /** Crypto key for the cipher. */
    final Key key; // package protected for access by crypto classes; do not expose futher

    /** the algorithm parameters */
    private final AlgorithmParameterSpec params;

    /** Flag to mark whether the input stream is closed. */
    private boolean closed;

    /**
     * Flag to mark whether do final of the cipher to end the decrypting stream.
     */
    private boolean finalDone = false;

    /** The input data. */
    Input input; // package protected for access by crypto classes; do not expose futher

    /**
     * Input data buffer. The data starts at inBuffer.position() and ends at to
     * inBuffer.limit().
     */
    ByteBuffer inBuffer; // package protected for access by crypto classes; do not expose futher

    /**
     * The decrypted data buffer. The data starts at outBuffer.position() and
     * ends at outBuffer.limit().
     */
    ByteBuffer outBuffer; // package protected for access by crypto classes; do not expose futher

    // stream related configuration keys
    /**
     * The default value of the buffer size for stream.
     */
    private static final int STREAM_BUFFER_SIZE_DEFAULT = 8192;

    private static final int MIN_BUFFER_SIZE = 512;

    /**
     * Constructs a {@link CryptoInputStream}.
     *
     * @param transformation the name of the transformation, e.g.,
     * <i>AES/CBC/PKCS5Padding</i>.
     * See the Java Cryptography Architecture Standard Algorithm Name Documentation
     * for information about standard transformation names.
     * @param props The {@code Properties} class represents a set of
     *        properties.
     * @param in the input stream.
     * @param key crypto key for the cipher.
     * @param params the algorithm parameters.
     * @throws IOException if an I/O error occurs.
     */
    public CryptoInputStream(final String transformation,
            final Properties props, final InputStream in, final Key key,
            final AlgorithmParameterSpec params) throws IOException {
        this(in, Utils.getCipherInstance(transformation, props),
                CryptoInputStream.getBufferSize(props), key, params);
    }

    /**
     * Constructs a {@link CryptoInputStream}.
     *
     * @param transformation the name of the transformation, e.g.,
     * <i>AES/CBC/PKCS5Padding</i>.
     * See the Java Cryptography Architecture Standard Algorithm Name Documentation
     * for information about standard transformation names.
     * @param props The {@code Properties} class represents a set of
     *        properties.
     * @param in the ReadableByteChannel object.
     * @param key crypto key for the cipher.
     * @param params the algorithm parameters.
     * @throws IOException if an I/O error occurs.
     */
    public CryptoInputStream(final String transformation,
            final Properties props, final ReadableByteChannel in, final Key key,
            final AlgorithmParameterSpec params) throws IOException {
        this(in, Utils.getCipherInstance(transformation, props), CryptoInputStream
                .getBufferSize(props), key, params);
    }

    /**
     * Constructs a {@link CryptoInputStream}.
     *
     * @param cipher the cipher instance.
     * @param in the input stream.
     * @param bufferSize the bufferSize.
     * @param key crypto key for the cipher.
     * @param params the algorithm parameters.
     * @throws IOException if an I/O error occurs.
     */
    protected CryptoInputStream(final InputStream in, final CryptoCipher cipher,
            final int bufferSize, final Key key, final AlgorithmParameterSpec params)
            throws IOException {
        this(new StreamInput(in, bufferSize), cipher, bufferSize, key, params);
    }

    /**
     * Constructs a {@link CryptoInputStream}.
     *
     * @param in the ReadableByteChannel instance.
     * @param cipher the cipher instance.
     * @param bufferSize the bufferSize.
     * @param key crypto key for the cipher.
     * @param params the algorithm parameters.
     * @throws IOException if an I/O error occurs.
     */
    protected CryptoInputStream(final ReadableByteChannel in, final CryptoCipher cipher,
            final int bufferSize, final Key key, final AlgorithmParameterSpec params)
            throws IOException {
        this(new ChannelInput(in), cipher, bufferSize, key, params);
    }

    /**
     * Constructs a {@link CryptoInputStream}.
     *
     * @param input the input data.
     * @param cipher the cipher instance.
     * @param bufferSize the bufferSize.
     * @param key crypto key for the cipher.
     * @param params the algorithm parameters.
     * @throws IOException if an I/O error occurs.
     */
    protected CryptoInputStream(final Input input, final CryptoCipher cipher, final int bufferSize,
            final Key key, final AlgorithmParameterSpec params) throws IOException {
        this.input = input;
        this.cipher = cipher;
        this.bufferSize = CryptoInputStream.checkBufferSize(cipher, bufferSize);

        this.key = key;
        this.params = params;
        if (!(params instanceof IvParameterSpec)) {
            // other AlgorithmParameterSpec such as GCMParameterSpec is not
            // supported now.
            throw new IOException("Illegal parameters");
        }

        inBuffer = ByteBuffer.allocateDirect(this.bufferSize);
        outBuffer = ByteBuffer.allocateDirect(this.bufferSize
                + cipher.getBlockSize());
        outBuffer.limit(0);

        initCipher();
    }

    /**
     * Overrides the {@link java.io.InputStream#read()}. Reads the next byte of
     * data from the input stream.
     *
     * @return the next byte of data, or {@code -1} if the end of the
     *         stream is reached.
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public int read() throws IOException {
        int n;
        while ((n = read(oneByteBuf, 0, 1)) == 0) { //NOPMD
            /* no op */
        }
        return (n == -1) ? -1 : oneByteBuf[0] & 0xff;
    }

    /**
     * Overrides the {@link java.io.InputStream#read(byte[], int, int)}.
     * Decryption is buffer based. If there is data in {@link #outBuffer}, then
     * read it out of this buffer. If there is no data in {@link #outBuffer},
     * then read more from the underlying stream and do the decryption.
     *
     * @param array the buffer into which the decrypted data is read.
     * @param off the buffer offset.
     * @param len the maximum number of decrypted data bytes to read.
     * @return int the total number of decrypted data bytes read into the
     *         buffer.
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public int read(final byte[] array, final int off, final int len) throws IOException {
        checkStream();
        Objects.requireNonNull(array, "array");
        if (off < 0 || len < 0 || len > array.length - off) {
            throw new IndexOutOfBoundsException();
        } else if (len == 0) {
            return 0;
        }

        final int remaining = outBuffer.remaining();
        if (remaining > 0) {
            // Satisfy the read with the existing data
            final int n = Math.min(len, remaining);
            outBuffer.get(array, off, n);
            return n;
        }
        // No data in the out buffer, try read new data and decrypt it
        // we loop for new data
        int nd = 0;
        while (nd == 0) {
            nd = decryptMore();
        }
        if (nd < 0) {
            return nd;
        }

        final int n = Math.min(len, outBuffer.remaining());
        outBuffer.get(array, off, n);
        return n;
    }

    /**
     * Overrides the {@link java.io.InputStream#skip(long)}. Skips over and
     * discards {@code n} bytes of data from this input stream.
     *
     * @param n the number of bytes to be skipped.
     * @return the actual number of bytes skipped.
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public long skip(final long n) throws IOException {
        Utils.checkArgument(n >= 0, "Negative skip length.");
        checkStream();

        if (n == 0) {
            return 0;
        }

        long remaining = n;
        int nd;

        while (remaining > 0) {
            if (remaining <= outBuffer.remaining()) {
                // Skip in the remaining buffer
                final int pos = outBuffer.position() + (int) remaining;
                outBuffer.position(pos);

                remaining = 0;
                break;
            }
            remaining -= outBuffer.remaining();
            outBuffer.clear();

            // we loop for new data
            nd = 0;
            while (nd == 0) {
                nd = decryptMore();
            }
            if (nd < 0) {
                break;
            }
        }

        return n - remaining;
    }

    /**
     * Overrides the {@link InputStream#available()}. Returns an estimate of the
     * number of bytes that can be read (or skipped over) from this input stream
     * without blocking by the next invocation of a method for this input
     * stream.
     *
     * @return an estimate of the number of bytes that can be read (or skipped
     *         over) from this input stream without blocking or {@code 0} when
     *         it reaches the end of the input stream.
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public int available() throws IOException {
        checkStream();

        return input.available() + outBuffer.remaining();
    }

    /**
     * Overrides the {@link InputStream#close()}. Closes this input stream and
     * releases any system resources associated with the stream.
     *
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }

        input.close();
        freeBuffers();
        cipher.close();
        super.close();
        closed = true;
    }

    /**
     * Overrides the {@link java.io.InputStream#mark(int)}. For
     * {@link CryptoInputStream},we don't support the mark method.
     *
     * @param readlimit the maximum limit of bytes that can be read before the
     *        mark position becomes invalid.
     */
    @Override
    public void mark(final int readlimit) {
    }

    /**
     * Overrides the {@link InputStream#reset()}. For {@link CryptoInputStream}
     * ,we don't support the reset method.
     *
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public void reset() throws IOException {
        throw new IOException("Mark/reset not supported");
    }

    /**
     * Overrides the {@link InputStream#markSupported()}.
     *
     * @return false,the {@link CtrCryptoInputStream} don't support the mark
     *         method.
     */
    @Override
    public boolean markSupported() {
        return false;
    }

    /**
     * Overrides the {@link java.nio.channels.Channel#isOpen()}.
     *
     * @return <tt>true</tt> if, and only if, this channel is open.
     */
    @Override
    public boolean isOpen() {
        return !closed;
    }

    /**
     * Overrides the
     * {@link java.nio.channels.ReadableByteChannel#read(ByteBuffer)}. Reads a
     * sequence of bytes from this channel into the given buffer.
     *
     * @param dst The buffer into which bytes are to be transferred.
     * @return The number of bytes read, possibly zero, or <tt>-1</tt> if the
     *         channel has reached end-of-stream.
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public int read(final ByteBuffer dst) throws IOException {
        checkStream();
        int remaining = outBuffer.remaining();
        if (remaining <= 0) {
            // Decrypt more data
            // we loop for new data
            int nd = 0;
            while (nd == 0) {
                nd = decryptMore();
            }

            if (nd < 0) {
                return -1;
            }
        }

        // Copy decrypted data from outBuffer to dst
        remaining = outBuffer.remaining();
        final int toRead = dst.remaining();
        if (toRead <= remaining) {
            final int limit = outBuffer.limit();
            outBuffer.limit(outBuffer.position() + toRead);
            dst.put(outBuffer);
            outBuffer.limit(limit);
            return toRead;
        }
        dst.put(outBuffer);
        return remaining;
    }

    /**
     * Gets the buffer size.
     *
     * @return the bufferSize.
     */
    protected int getBufferSize() {
        return bufferSize;
    }

    /**
     * Gets the key.
     *
     * @return the key.
     */
    protected Key getKey() {
        return key;
    }

    /**
     * Gets the internal CryptoCipher.
     *
     * @return the cipher instance.
     */
    protected CryptoCipher getCipher() {
        return cipher;
    }

    /**
     * Gets the specification of cryptographic parameters.
     *
     * @return the params.
     */
    protected AlgorithmParameterSpec getParams() {
        return params;
    }

    /**
     * Gets the input.
     *
     * @return the input.
     */
    protected Input getInput() {
        return input;
    }

    /**
     * Initializes the cipher.
     *
     * @throws IOException if an I/O error occurs.
     */
    protected void initCipher() throws IOException {
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, params);
        } catch (final InvalidKeyException e) {
            throw new IOException(e);
        } catch (final InvalidAlgorithmParameterException e) {
            throw new IOException(e);
        }
    }

    /**
     * Decrypts more data by reading the under layer stream. The decrypted data
     * will be put in the output buffer. If the end of the under stream reached,
     * we will do final of the cipher to finish all the decrypting of data.
     *
     * @return The number of decrypted data.
     *           return -1 (if end of the decrypted stream)
     *           return 0 (no data now, but could have more later)
     * @throws IOException if an I/O error occurs.
     */
    protected int decryptMore() throws IOException {
        if (finalDone) {
            return -1;
        }

        final int n = input.read(inBuffer);
        if (n < 0) {
            // The stream is end, finalize the cipher stream
            decryptFinal();

            // Satisfy the read with the remaining
            final int remaining = outBuffer.remaining();
            if (remaining > 0) {
                return remaining;
            }

            // End of the stream
            return -1;
        } else if (n == 0) {
            // No data is read, but the stream is not end yet
            return 0;
        } else {
            decrypt();
            return outBuffer.remaining();
        }
    }

    /**
     * Does the decryption using inBuffer as input and outBuffer as output. Upon
     * return, inBuffer is cleared; the decrypted data starts at
     * outBuffer.position() and ends at outBuffer.limit().
     *
     * @throws IOException if an I/O error occurs.
     */
    protected void decrypt() throws IOException {
        // Prepare the input buffer and clear the out buffer
        inBuffer.flip();
        outBuffer.clear();

        try {
            cipher.update(inBuffer, outBuffer);
        } catch (final ShortBufferException e) {
            throw new IOException(e);
        }

        // Clear the input buffer and prepare out buffer
        inBuffer.clear();
        outBuffer.flip();
    }

    /**
     * Does final of the cipher to end the decrypting stream.
     *
     * @throws IOException if an I/O error occurs.
     */
    protected void decryptFinal() throws IOException {
        // Prepare the input buffer and clear the out buffer
        inBuffer.flip();
        outBuffer.clear();

        try {
            cipher.doFinal(inBuffer, outBuffer);
            finalDone = true;
        } catch (final ShortBufferException e) {
            throw new IOException(e);
        } catch (final IllegalBlockSizeException e) {
            throw new IOException(e);
        } catch (final BadPaddingException e) {
            throw new IOException(e);
        }

        // Clear the input buffer and prepare out buffer
        inBuffer.clear();
        outBuffer.flip();
    }

    /**
     * Checks whether the stream is closed.
     *
     * @throws IOException if an I/O error occurs.
     */
    protected void checkStream() throws IOException {
        if (closed) {
            throw new IOException("Stream closed");
        }
    }

    /** Forcibly free the direct buffers. */
    protected void freeBuffers() {
        CryptoInputStream.freeDirectBuffer(inBuffer);
        CryptoInputStream.freeDirectBuffer(outBuffer);
    }

    /**
     * Forcibly free the direct buffer.
     *
     * @param buffer the bytebuffer to be freed.
     */
    static void freeDirectBuffer(final ByteBuffer buffer) {
        try {
            /* Using reflection to implement sun.nio.ch.DirectBuffer.cleaner()
            .clean(); */
            final String SUN_CLASS = "sun.nio.ch.DirectBuffer";
            final Class<?>[] interfaces = buffer.getClass().getInterfaces();

            for (final Class<?> clazz : interfaces) {
                if (clazz.getName().equals(SUN_CLASS)) {
                    final Object[] NO_PARAM = new Object[0];
                    /* DirectBuffer#cleaner() */
                    final Method getCleaner = Class.forName(SUN_CLASS).getMethod("cleaner");
                    final Object cleaner = getCleaner.invoke(buffer, NO_PARAM);
                    /* Cleaner#clean() */
                    final Method cleanMethod = Class.forName("sun.misc.Cleaner").getMethod("clean");
                    cleanMethod.invoke(cleaner, NO_PARAM);
                    return;
                }
            }
        } catch (final ReflectiveOperationException e) { // NOPMD
            // Ignore the Reflection exception.
        }
    }

    /**
     * Reads crypto buffer size.
     *
     * @param props The {@code Properties} class represents a set of
     *        properties.
     * @return the buffer size.
     * */
    static int getBufferSize(final Properties props) {
        final String bufferSizeStr = props.getProperty(CryptoInputStream.STREAM_BUFFER_SIZE_KEY);
        if (bufferSizeStr == null || bufferSizeStr.isEmpty()) {
            return CryptoInputStream.STREAM_BUFFER_SIZE_DEFAULT;
        }
        return Integer.parseInt(bufferSizeStr);
    }

    /**
     * Checks whether the cipher is supported streaming.
     *
     * @param cipher the {@link CryptoCipher} instance.
     * @throws IOException if an I/O error occurs.
     */
    static void checkStreamCipher(final CryptoCipher cipher)
            throws IOException {
        if (!cipher.getAlgorithm().equals("AES/CTR/NoPadding")) {
            throw new IOException("AES/CTR/NoPadding is required");
        }
    }

    /**
     * Checks and floors buffer size.
     *
     * @param cipher the {@link CryptoCipher} instance.
     * @param bufferSize the buffer size.
     * @return the remaining buffer size.
     */
    static int checkBufferSize(final CryptoCipher cipher, final int bufferSize) {
        Utils.checkArgument(bufferSize >= CryptoInputStream.MIN_BUFFER_SIZE,
                "Minimum value of buffer size is " + CryptoInputStream.MIN_BUFFER_SIZE + ".");
        return bufferSize - bufferSize
                % cipher.getBlockSize();
    }
}
