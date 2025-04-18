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
package org.apache.commons.crypto.utils;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.crypto.stream.input.Input;
import org.apache.commons.io.IOUtils;

/**
 * General utility methods for working with IO.
 */
public final class IoUtils {

    /**
     * Closes the Closeable objects and <strong>ignore</strong> any {@link IOException} or
     * null pointers. Must only be used for cleanup in exception handlers.
     *
     * @param closeables the objects to close.
     */
    public static void cleanup(final Closeable... closeables) {
        if (closeables != null) {
            for (final Closeable c : closeables) {
                closeQuietly(c);
            }
        }
    }

    /**
     * Closes the given {@link Closeable} quietly by ignoring IOException.
     *
     * @param closeable The resource to close.
     * @since 1.1.0
     */
    public static void closeQuietly(final Closeable closeable) {
        IOUtils.closeQuietly(closeable);
    }

    /**
     * Does the readFully based on Input's positioned read. This does not change
     * the current offset of the stream and is thread-safe.
     *
     * @param in the input source.
     * @param position the given position.
     * @param buffer the buffer to be read.
     * @param length the maximum number of bytes to read.
     * @param offset the start offset in array buffer.
     * @throws IOException if an I/O error occurs.
     */
    public static void readFully(final Input in, final long position, final byte[] buffer,
            final int offset, final int length) throws IOException {
        int nread = 0;
        while (nread < length) {
            final int nbytes = in.read(position + nread, buffer, offset + nread,
                    length - nread);
            if (nbytes < 0) {
                throw new IOException(
                        "End of stream reached before reading fully.");
            }
            nread += nbytes;
        }
    }

    /**
     * Does the readFully based on the Input read.
     *
     * @param in the input stream of bytes.
     * @param buf the buffer to be read.
     * @param off the start offset in array buffer.
     * @param len the maximum number of bytes to read.
     * @throws IOException if an I/O error occurs.
     */
    public static void readFully(final InputStream in, final byte[] buf, int off, final int len)
            throws IOException {
        int toRead = len;
        while (toRead > 0) {
            final int ret = in.read(buf, off, toRead);
            if (ret < 0) {
                throw new IOException("Premature EOF from inputStream");
            }
            toRead -= ret;
            off += ret;
        }
    }

    /**
     * The private constructor of {@link IoUtils}.
     */
    private IoUtils() {
    }
}
