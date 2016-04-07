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

  public StreamInput(InputStream inputStream, int bufferSize) {
    this.in = inputStream;
    this.bufferSize = bufferSize;
  }

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

  @Override
  public long skip(long n) throws IOException {
    return in.skip(n);
  }

  @Override
  public int available() throws IOException {
    return in.available();
  }

  @Override
  public int read(long position, byte[] buffer, int offset, int length)
      throws IOException {
    throw new UnsupportedOperationException(
        "Positioned read is not supported by this implementation");
  }

  @Override
  public void seek(long position) throws IOException {
    throw new UnsupportedOperationException(
        "Seek is not supported by this implementation");
  }

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
