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

package com.intel.chimera.input;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;

/**
 * The PositionedChannelInput class takes a <code>SeekableByteChannel</code> object and
 * wraps it as <code>Input</code> object acceptable by <code>PositionedCryptoInputStream</code>.
 */
public class PositionedChannelInput implements Input {

  private SeekableByteChannel channel;

  public PositionedChannelInput(
          SeekableByteChannel channel) {
    this.channel = channel;
  }

  @Override
  public int read(ByteBuffer dst) throws IOException {
    return channel.read(dst);
  }

  @Override
  public long skip(long n) throws IOException {
    if (n <= 0) {
      return 0;
    }

    long currentPosition = channel.position();
    long size = channel.size();

    if (size - currentPosition < n) {
      channel.position(size);
      return size - currentPosition;
    } else {
      channel.position(currentPosition + n);
      return n;
    }
  }

  @Override
  public int read(long position, byte[] buffer, int offset, int length)
          throws IOException {
    if (position < 0 || position > channel.size() - 1) {
      return 0;
    }

    if (offset < 0 || offset > buffer.length - 1) {
      return 0;
    }

    if (length < 0) {
      return 0;
    }

    int bufferAllocated = length;
    if (offset + length > buffer.length - 1) {
      bufferAllocated = buffer.length - offset;
    }

    ByteBuffer byteBuffer = ByteBuffer.allocate(bufferAllocated);
    long oldPosition = channel.position();
    channel.position(position);
    int readLength = channel.read(byteBuffer);
    channel.position(oldPosition);
    System.arraycopy(byteBuffer.array(), 0, buffer, offset, readLength);
    return readLength;
  }

  @Override
  public void readFully(long position, byte[] buffer, int offset, int length)
          throws IOException {
    int readLength = read(position, buffer, offset, length);
    if (readLength != length) {
      throw new EOFException("End of channel reached before reading fully.");
    }
  }

  @Override
  public void seek(long pos) throws IOException {
    if (pos >= 0) {
      channel.position(pos);
    }
  }

  @Override
  public void close() throws IOException {
    channel.close();
  }

  @Override
  public int available() throws IOException {
    return 0;
  }

}
