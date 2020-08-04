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
package org.apache.commons.crypto.stream.input;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * The Input interface abstract the input source of
 * {@code CryptoInputStream} so that different implementation of input can
 * be used. The implementation Input interface will usually wraps an input
 * mechanism such as {@code InputStream} or
 * {@code ReadableByteChannel}.
 */
public interface Input {
    /**
     * Reads a sequence of bytes from input into the given buffer.
     *
     * <p>
     * An attempt is made to read up to <i>r</i> bytes from the input, where
     * <i>r</i> is the number of bytes remaining in the buffer, that is,
     * {@code dst.remaining()}, at the moment this method is invoked.
     *
     * <p>
     * Suppose that a byte sequence of length <i>n</i> is read, where {@code 0}
     * &nbsp;{@code <=}&nbsp;<i>n</i>&nbsp;{@code <=}&nbsp;<i>r</i>.
     * This byte sequence will be transferred into the buffer so that the first
     * byte in the sequence is at index <i>p</i> and the last byte is at index
     * <i>p</i>&nbsp;{@code +}&nbsp;<i>n</i>&nbsp;{@code -}&nbsp;{@code 1},
     * where <i>p</i> is the buffer's position at the moment this method is
     * invoked. Upon return the buffer's position will be equal to
     * <i>p</i>&nbsp;{@code +}&nbsp;<i>n</i>; its limit will not have changed.
     *
     * @param dst The buffer into which bytes are to be transferred.
     * @return the total number of bytes read into the buffer, or
     *         {@code -1} if there is no more data because the end of the
     *         stream has been reached.
     * @throws IOException If some other I/O error occurs.
     */
    int read(ByteBuffer dst) throws IOException;

    /**
     * Skips over and discards {@code n} bytes of data from this input The
     * {@code skip} method may, for a variety of reasons, end up skipping
     * over some smaller number of bytes, possibly {@code 0}. This may
     * result from any of a number of conditions; reaching end of file before
     * {@code n} bytes have been skipped is only one possibility. The
     * actual number of bytes skipped is returned. If {@code n} is
     * negative, no bytes are skipped.
     *
     * <p>
     * The {@code skip} method of this class creates a byte array and then
     * repeatedly reads into it until {@code n} bytes have been read or the
     * end of the stream has been reached. Subclasses are encouraged to provide
     * a more efficient implementation of this method. For instance, the
     * implementation may depend on the ability to seek.
     *
     * @param n the number of bytes to be skipped.
     * @return the actual number of bytes skipped.
     * @throws IOException if the stream does not support seek, or if some
     *            other I/O error occurs.
     */
    long skip(long n) throws IOException;

    /**
     * Returns an estimate of the number of bytes that can be read (or skipped
     * over) from this input without blocking by the next invocation of a method
     * for this input stream. The next invocation might be the same thread or
     * another thread. A single read or skip of this many bytes will not block,
     * but may read or skip fewer bytes.
     *
     * <p>
     * It is never correct to use the return value of this method to allocate a
     * buffer intended to hold all data in this stream.
     *
     * @return an estimate of the number of bytes that can be read (or skipped
     *         over) from this input stream without blocking or {@code 0} when
     *         it reaches the end of the input stream.
     * @throws IOException if an I/O error occurs.
     */
    int available() throws IOException;

    /**
     * Reads up to the specified number of bytes from a given position within a
     * stream and return the number of bytes read. This does not change the
     * current offset of the stream and is thread-safe.
     *
     * An implementation may not support positioned read. If the implementation
     * doesn't support positioned read, it throws UnsupportedOperationException.
     *
     * @param position the given position within a stream.
     * @param buffer the buffer into which the data is read.
     * @param offset the start offset in array buffer.
     * @param length the maximum number of bytes to read.
     * @return the total number of bytes read into the buffer, or
     *         {@code -1} if there is no more data because the end of the
     *         stream has been reached.
     * @throws IOException if an I/O error occurs.
     */
    int read(long position, byte[] buffer, int offset, int length)
            throws IOException;

    /**
     * Seeks to the given offset from the start of the stream. The next read()
     * will be from that location.
     *
     * An implementation may not support seek. If the implementation doesn't
     * support seek, it throws UnsupportedOperationException.
     *
     * @param position the offset from the start of the stream.
     * @throws IOException if an I/O error occurs.
     */
    void seek(long position) throws IOException;

    /**
     * Closes this input and releases any system resources associated with the
     * under layer input.
     *
     * @throws IOException if an I/O error occurs.
     */
    void close() throws IOException;
}
