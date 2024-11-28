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
import java.nio.ByteBuffer;
import java.nio.channels.WritableByteChannel;
import java.util.Objects;

import org.apache.commons.crypto.stream.CryptoOutputStream;

/**
 * The ChannelOutput class takes a {@link WritableByteChannel} object and
 * wraps it as {@code Output} object acceptable by
 * {@link CryptoOutputStream} as the output target.
 */
public class ChannelOutput implements Output {

    private final WritableByteChannel channel;

    /**
     * Constructs a
     * {@link org.apache.commons.crypto.stream.output.ChannelOutput}.
     *
     * @param channel the WritableByteChannel object.
     * @throws NullPointerException if channel is null.
     */
    public ChannelOutput(final WritableByteChannel channel) {
        this.channel = Objects.requireNonNull(channel, "channel");
    }

    /**
     * Overrides the {@link Output#close()}. Closes this output and releases any
     * system resources associated with the under layer output.
     *
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public void close() throws IOException {
        channel.close();
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
        // noop
    }

    /**
     * Overrides the
     * {@link org.apache.commons.crypto.stream.output.Output#write(ByteBuffer)}.
     * Writes a sequence of bytes to this output from the given buffer.
     *
     * @param src The buffer from which bytes are to be retrieved.
     * @return The number of bytes written, possibly zero.
     * @throws IOException if an I/O error occurs.
     */
    @Override
    public int write(final ByteBuffer src) throws IOException {
        return channel.write(src);
    }
}
