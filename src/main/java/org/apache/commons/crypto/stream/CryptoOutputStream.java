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
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;
import java.util.Properties;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.stream.output.ChannelOutput;
import org.apache.commons.crypto.stream.output.Output;
import org.apache.commons.crypto.stream.output.StreamOutput;
import org.apache.commons.crypto.utils.Utils;

/**
 * {@link CryptoOutputStream} encrypts data and writes to the under layer
 * output. It supports any mode of operations such as AES CBC/CTR/GCM mode in
 * concept. It is not thread-safe.
 * <p>
 * This class should only be used with blocking sinks. Using this class to wrap
 * a non-blocking sink may lead to high CPU usage.
 * </p>
 */

public class CryptoOutputStream extends OutputStream implements
        WritableByteChannel {
    private final byte[] oneByteBuf = new byte[1];

    /** The output. */
    Output output; // package protected for access by crypto classes; do not expose futher

    /** the CryptoCipher instance */
    final CryptoCipher cipher; // package protected for access by crypto classes; do not expose futher

    /** The buffer size. */
    private final int bufferSize;

    /** Crypto key for the cipher. */
    final Key key; // package protected for access by crypto classes; do not expose futher

    /** the algorithm parameters */
    private final AlgorithmParameterSpec params;

    /** Flag to mark whether the output stream is closed. */
    private boolean closed;

    /**
     * Input data buffer. The data starts at inBuffer.position() and ends at
     * inBuffer.limit().
     */
    ByteBuffer inBuffer; // package protected for access by crypto classes; do not expose futher

    /**
     * Encrypted data buffer. The data starts at outBuffer.position() and ends
     * at outBuffer.limit().
     */
    ByteBuffer outBuffer; // package protected for access by crypto classes; do not expose futher

    /**
     * Constructs a {@link CryptoOutputStream}.
     *
     * @param transformation the name of the transformation, e.g.,
     * <i>AES/CBC/PKCS5Padding</i>.
     * See the Java Cryptography Architecture Standard Algorithm Name Documentation
     * for information about standard transformation names.
     * @param props The {@code Properties} class represents a set of
     *        properties.
     * @param out the output stream.
     * @param key crypto key for the cipher.
     * @param params the algorithm parameters.
     * @throws IOException if an I/O error occurs.
     */

    public CryptoOutputStream(String transformation,
            Properties props, OutputStream out, Key key,
            AlgorithmParameterSpec params) throws IOException {
        this(out, Utils.getCipherInstance(transformation, props),
                CryptoInputStream.getBufferSize(props), key, params);

    }

    /**
     * Constructs a {@link CryptoOutputStream}.
     *
     * @param transformation the name of the transformation, e.g.,
     * <i>AES/CBC/PKCS5Padding</i>.
     * See the Java Cryptography Architecture Standard Algorithm Name Documentation
     * for information about standard transformation names.
     * @param props The {@code Properties} class represents a set of
     *        properties.
     * @param out the WritableByteChannel instance.
     * @param key crypto key for the cipher.
     * @param params the algorithm parameters.
     * @throws IOException if an I/O error occurs.
     */
    public CryptoOutputStream(String transformation,
            Properties props, WritableByteChannel out, Key key,
            AlgorithmParameterSpec params) throws IOException {
        this(out, Utils.getCipherInstance(transformation, props), CryptoInputStream
                .getBufferSize(props), key, params);

    }

    /**
     * Constructs a {@link CryptoOutputStream}.
     *
     * @param out the output stream.
     * @param cipher the CryptoCipher instance.
     * @param bufferSize the bufferSize.
     * @param key crypto key for the cipher.
     * @param params the algorithm parameters.
     * @throws IOException if an I/O error occurs.
     */
    protected CryptoOutputStream(OutputStream out, CryptoCipher cipher,
            int bufferSize, Key key, AlgorithmParameterSpec params)
            throws IOException {
        this(new StreamOutput(out, bufferSize), cipher, bufferSize, key, params);
    }

    /**
     * Constructs a {@link CryptoOutputStream}.
     *
     * @param channel the WritableByteChannel instance.
     * @param cipher the cipher instance.
     * @param bufferSize the bufferSize.
     * @param key crypto key for the cipher.
     * @param params the algorithm parameters.
     * @throws IOException if an I/O error occurs.
     */
    protected CryptoOutputStream(WritableByteChannel channel, CryptoCipher cipher,
            int bufferSize, Key key, AlgorithmParameterSpec params)
            throws IOException {
        this(new ChannelOutput(channel), cipher, bufferSize, key, params);
    }

    /**
     * Constructs a {@link CryptoOutputStream}.
     *
     * @param output the output stream.
     * @param cipher the CryptoCipher instance.
     * @param bufferSize the bufferSize.
     * @param key crypto key for the cipher.
     * @param params the algorithm parameters.
     * @throws IOException if an I/O error occurs.
     */
    protected CryptoOutputStream(Output output, CryptoCipher cipher,
            int bufferSize, Key key, AlgorithmParameterSpec params)
            throws IOException {

        this.output = output;
        this.bufferSize = CryptoInputStream.checkBufferSize(cipher, bufferSize);
        this.cipher = cipher;

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

        initCipher();
    }

    /**
     * Overrides the {@link java.io.OutputStream#write(byte[])}. Writes the
     * specified byte to this output stream.
     *
     * @param b the data.
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public void write(int b) throws IOException {
        oneByteBuf[0] = (byte) (b & 0xff);
        write(oneByteBuf, 0, oneByteBuf.length);
    }

    /**
     * Overrides the {@link java.io.OutputStream#write(byte[], int, int)}.
     * Encryption is buffer based. If there is enough room in {@link #inBuffer},
     * then write to this buffer. If {@link #inBuffer} is full, then do
     * encryption and write data to the underlying stream.
     *
     * @param array the data.
     * @param off the start offset in the data.
     * @param len the number of bytes to write.
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public void write(byte[] array, int off, int len) throws IOException {
        checkStream();
        Objects.requireNonNull(array, "array");
        if (off < 0 || len < 0 || off > array.length || len > array.length - off) {
            throw new IndexOutOfBoundsException();
        }

        while (len > 0) {
            final int remaining = inBuffer.remaining();
            if (len < remaining) {
                inBuffer.put(array, off, len);
                len = 0;
            } else {
                inBuffer.put(array, off, remaining);
                off += remaining;
                len -= remaining;
                encrypt();
            }
        }
    }

    /**
     * Overrides the {@link OutputStream#flush()}. To flush, we need to encrypt
     * the data in the buffer and write to the underlying stream, then do the
     * flush.
     *
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public void flush() throws IOException {
        checkStream();
        encrypt();
        output.flush();
        super.flush();
    }

    /**
     * Overrides the {@link OutputStream#close()}. Closes this output stream and
     * releases any system resources associated with this stream.
     *
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }

        try {
            encryptFinal();
            output.close();
            freeBuffers();
            cipher.close();
            super.close();
        } finally {
            closed = true;
        }
    }

    /**
     * Overrides the {@link java.nio.channels.Channel#isOpen()}. Tells whether or not this channel
     * is open.
     *
     * @return <tt>true</tt> if, and only if, this channel is open
     */
    @Override
    public boolean isOpen() {
        return !closed;
    }

    /**
     * Overrides the
     * {@link java.nio.channels.WritableByteChannel#write(ByteBuffer)}. Writes a
     * sequence of bytes to this channel from the given buffer.
     *
     * @param src The buffer from which bytes are to be retrieved.
     * @return The number of bytes written, possibly zero.
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public int write(ByteBuffer src) throws IOException {
        checkStream();
        final int len = src.remaining();
        int remaining = len;
        while (remaining > 0) {
            final int space = inBuffer.remaining();
            if (remaining < space) {
                inBuffer.put(src);
                remaining = 0;
            } else {
                // to void copy twice, we set the limit to copy directly
                final int oldLimit = src.limit();
                final int newLimit = src.position() + space;
                src.limit(newLimit);

                inBuffer.put(src);

                // restore the old limit
                src.limit(oldLimit);

                remaining -= space;
                encrypt();
            }
        }

        return len;
    }

    /**
     * Initializes the cipher.
     *
     * @throws IOException if an I/O error occurs.
     */
    protected void initCipher() throws IOException {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, params);
        } catch (InvalidKeyException e) {
            throw new IOException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IOException(e);
        }
    }

    /**
     * Does the encryption, input is {@link #inBuffer} and output is
     * {@link #outBuffer}.
     *
     * @throws IOException if an I/O error occurs.
     */
    protected void encrypt() throws IOException {

        inBuffer.flip();
        outBuffer.clear();

        try {
            cipher.update(inBuffer, outBuffer);
        } catch (ShortBufferException e) {
            throw new IOException(e);
        }

        inBuffer.clear();
        outBuffer.flip();

        // write to output
        while (outBuffer.hasRemaining()) {
            output.write(outBuffer);
        }
    }

    /**
     * Does final encryption of the last data.
     *
     * @throws IOException if an I/O error occurs.
     */
    protected void encryptFinal() throws IOException {
        inBuffer.flip();
        outBuffer.clear();

        try {
            cipher.doFinal(inBuffer, outBuffer);
        } catch (ShortBufferException e) {
            throw new IOException(e);
        } catch (IllegalBlockSizeException e) {
            throw new IOException(e);
        } catch (BadPaddingException e) {
            throw new IOException(e);
        }

        inBuffer.clear();
        outBuffer.flip();

        // write to output
        while (outBuffer.hasRemaining()) {
            output.write(outBuffer);
        }
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
     * Gets the outBuffer.
     *
     * @return the outBuffer.
     */
    protected ByteBuffer getOutBuffer() {
        return outBuffer;
    }

    /**
     * Gets the internal Cipher.
     *
     * @return the cipher instance.
     */
    protected CryptoCipher getCipher() {
        return cipher;
    }

    /**
     * Gets the buffer size.
     *
     * @return the buffer size.
     */
    protected int getBufferSize() {
        return bufferSize;
    }

    /**
     * Gets the inBuffer.
     *
     * @return the inBuffer.
     */
    protected ByteBuffer getInBuffer() {
        return inBuffer;
    }
}
