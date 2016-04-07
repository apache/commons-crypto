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
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;

/**
 * The ChannelInput class takes a <code>ReadableByteChannel</code> object and
 * wraps it as <code>Input</code> object acceptable by <code>CryptoInputStream</code>.
 */
public class ChannelInput implements Input {
  private static final int SKIP_BUFFER_SIZE = 2048;

  private ByteBuffer buf;
  private ReadableByteChannel channel;

  public ChannelInput(
      ReadableByteChannel channel) {
    this.channel = channel;
  }

  @Override
  public int read(ByteBuffer dst) throws IOException {
    return channel.read(dst);
  }

  @Override
  public long skip(long n) throws IOException {
    long remaining = n;
    int nr;

    if (n <= 0) {
      return 0;
    }

    int size = (int)Math.min(SKIP_BUFFER_SIZE, remaining);
    ByteBuffer skipBuffer = getSkipBuf();
    while (remaining > 0) {
      skipBuffer.clear();
      skipBuffer.limit((int)Math.min(size, remaining));
      nr = read(skipBuffer);
      if (nr < 0) {
        break;
      }
      remaining -= nr;
    }

    return n - remaining;
  }

  @Override
  public int available() throws IOException {
    return 0;
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
    channel.close();
  }

  private ByteBuffer getSkipBuf() {
    if (buf == null) {
      buf = ByteBuffer.allocate(SKIP_BUFFER_SIZE);
    }
    return buf;
  }
}
