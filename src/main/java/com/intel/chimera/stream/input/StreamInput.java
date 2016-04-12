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
package com.intel.chimera.stream.input;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

/**
 * The StreamInput class takes a <code>InputStream</code> object and
 * wraps it as <code>Input</code> object acceptable by <code>CryptoInputStream</code>.
 */
public class StreamInput implements Input {
  private byte[] buf;
  private int bufferSize;
  InputStream in;

  /**
   * Constructs a {@link com.intel.chimera.stream.input.StreamInput}.
   *
   * @param inputStream the inputstream object.
   * @param bufferSize the buffersize.
   */
  public StreamInput(InputStream inputStream, int bufferSize) {
    this.in = inputStream;
    this.bufferSize = bufferSize;
  }

  /**
   * Overrides the {@link com.intel.chimera.stream.input.Input#read(ByteBuffer)}.
   * Reads a sequence of bytes from input into the given buffer.
   *
   * @param  dst
   *         The buffer into which bytes are to be transferred.
   *
   * @return the total number of bytes read into the buffer, or
   *          <code>-1</code> if there is no more data because the end of
   *          the stream has been reached.
   * @throws IOException if an I/O error occurs.
   */
  @Override
  public int read(ByteBuffer dst) throws IOException {
    int remaining = dst.remaining();
    final byte[] tmp = getBuf();
    int read = 0;
    while (remaining > 0) {
      final int n = in.read(tmp, 0, Math.min(remaining, bufferSize));
      if (n == -1) {
        if (read == 0) {
          read = -1;
        }
        break;
      } else if (n > 0) {
        dst.put(tmp, 0, n);
        read += n;
        remaining -= n;
      }
    }
    return read;
  }

  /**
   * Overrides the {@link com.intel.chimera.stream.input.Input#skip(long)}.
   * Skips over and discards <code>n</code> bytes of data from this input
   * stream.
   *
   * @param n the number of bytes to be skipped.
   * @return the actual number of bytes skipped.
   * @throws IOException if an I/O error occurs.
   */
  @Override
  public long skip(long n) throws IOException {
    return in.skip(n);
  }

  /**
   * Overrides the {@link Input#available()}.
   * Returns an estimate of the number of bytes that can be read (or
   * skipped over) from this input stream without blocking by the next
   * invocation of a method for this input stream. The next invocation
   * might be the same thread or another thread.  A single read or skip of this
   * many bytes will not block, but may read or skip fewer bytes.
   *
   * @return  an estimate of the number of bytes that can be read (or skipped
   *          over) from this input stream without blocking or {@code 0} when
   *          it reaches the end of the input stream.
   * @throws IOException if an I/O error occurs.
   */
  @Override
  public int available() throws IOException {
    return in.available();
  }

  /**
   * Overrides the {@link com.intel.chimera.stream.input.Input#read(long, byte[], int, int)}.
   * Reads up to <code>len</code> bytes of data from the input stream into
   * an array of bytes.  An attempt is made to read as many as
   * <code>len</code> bytes, but a smaller number may be read.
   * The number of bytes actually read is returned as an integer.
   *
   * @param position the given position within a stream.
   * @param buffer the buffer into which the data is read.
   * @param offset the start offset in array buffer.
   * @param length the maximum number of bytes to read.
   * @return the total number of bytes read into the buffer, or
   *          <code>-1</code> if there is no more data because the end of
   *          the stream has been reached.
   * @throws IOException if an I/O error occurs.
   */
  @Override
  public int read(long position, byte[] buffer, int offset, int length)
      throws IOException {
    throw new UnsupportedOperationException(
        "Positioned read is not supported by this implementation");
  }

  /**
   * Overrides the {@link com.intel.chimera.stream.input.Input#seek(long)}.
   * Seeks to the given offset from the start of the stream.
   * The next read() will be from that location.
   *
   * @param position the offset from the start of the stream.
   * @throws IOException if an I/O error occurs.
   */
  @Override
  public void seek(long position) throws IOException {
    throw new UnsupportedOperationException(
        "Seek is not supported by this implementation");
  }

  /**
   * Overrides the {@link com.intel.chimera.stream.input.Input#seek(long)}.
   * Closes this input and releases any system resources associated
   * with the under layer input.
   *
   * @throws IOException if an I/O error occurs.
   */
  @Override
  public void close() throws IOException {
    in.close();
  }

  private byte[] getBuf() {
    if (buf == null) {
      buf = new byte[bufferSize];
    }
    return buf;
  }
}
