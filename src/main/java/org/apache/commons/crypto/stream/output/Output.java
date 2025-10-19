 /*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.commons.crypto.stream.output;

import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.WritableByteChannel;

import org.apache.commons.crypto.stream.CryptoOutputStream;

/**
 * The Output interface abstract the output target of
 * {@link CryptoOutputStream} so that different implementation of output
 * can be used. The implementation Output interface will usually wrap an output
 * mechanism such as {@link OutputStream} or
 * {@link WritableByteChannel}.
 */
public interface Output extends Closeable {

    /**
     * Closes this output and releases any system resources associated with the
     * under layer output.
     *
     * @throws IOException if an I/O error occurs.
     */
    @Override
    void close() throws IOException;

    /**
     * Flushes this output and forces any buffered output bytes to be written
     * out if the under layer output method support. The general contract of
     * {@code flush} is that calling it is an indication that, if any bytes
     * previously written have been buffered by the implementation of the output
     * stream, such bytes should immediately be written to their intended
     * destination.
     *
     * @throws IOException if an I/O error occurs.
     */
    void flush() throws IOException;

    /**
     * Writes a sequence of bytes to this output from the given buffer.
     *
     * <p>
     * An attempt is made to write up to <em>r</em> bytes to the channel, where
     * <em>r</em> is the number of bytes remaining in the buffer, that is,
     * {@code src.remaining()}, at the moment this method is invoked.
     *
     * <p>
     * Suppose that a byte sequence of length <em>n</em> is written, where
     * {@code 0}&nbsp;{@code <=}&nbsp;<em>n</em>&nbsp;{@code <=}
     * &nbsp;<em>r</em>. This byte sequence will be transferred from the buffer
     * starting at index <em>p</em>, where <em>p</em> is the buffer's position at
     * the moment this method is invoked; the index of the last byte written
     * will be <em>p</em>&nbsp;{@code +}&nbsp;<em>n</em>&nbsp;{@code -}&nbsp;
     * {@code 1}. Upon return the buffer's position will be equal to
     * <em>p</em>&nbsp;{@code +}&nbsp;<em>n</em>; its limit will not have changed.
     *
     * @param src The buffer from which bytes are to be retrieved.
     * @return The number of bytes written, possibly zero.
     * @throws IOException If some other I/O error occurs.
     */
    int write(ByteBuffer src) throws IOException;
}
