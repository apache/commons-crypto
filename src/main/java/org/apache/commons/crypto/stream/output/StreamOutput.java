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
package org.apache.commons.crypto.stream.output;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.Objects;

import org.apache.commons.crypto.stream.CryptoOutputStream;

/**
 * The StreamOutput class takes a {@link OutputStream} object and wraps it
 * as {@link Output} object acceptable by {@link CryptoOutputStream}
 * as the output target.
 */
public class StreamOutput implements Output {
    private final byte[] buf;
    private final int bufferSize;
    private final OutputStream out;

    /**
     * Constructs a new instance.
     *
     * @param out the OutputStream object.
     * @param bufferSize the buffer size.
     * @throws NullPointerException if channel is null.
     */
    public StreamOutput(final OutputStream out, final int bufferSize) {
        this.out = Objects.requireNonNull(out, "out");
        this.bufferSize = bufferSize;
        this.buf = new byte[bufferSize];
    }

    /**
     * Overrides the {@link Output#close()}. Closes this output and releases any
     * system resources associated with the under layer output.
     *
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public void close() throws IOException {
        out.close();
    }

    /**
     * Overrides the {@link Output#flush()}. Flushes this output and forces any
     * buffered output bytes to be written out if the under layer output method
     * support.
     *
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public void flush() throws IOException {
        out.flush();
    }

    /**
     * Gets the output stream.
     *
     * @return the output stream.
     */
    protected OutputStream getOut() {
        return out;
    }

    /**
     * Overrides the
     * {@link org.apache.commons.crypto.stream.output.Output#write(ByteBuffer)}.
     * Writes a sequence of bytes to this output from the given buffer.
     *
     * @param src The buffer from which bytes are to be retrieved.
     *
     * @return The number of bytes written, possibly zero.
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public int write(final ByteBuffer src) throws IOException {
        final int len = src.remaining();

        int remaining = len;
        while (remaining > 0) {
            final int n = Math.min(remaining, bufferSize);
            src.get(buf, 0, n);
            out.write(buf, 0, n);
            remaining = src.remaining();
        }

        return len;
    }
}
