/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.commons.crypto.stream;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;

import static java.lang.Thread.sleep;

public class DummyChannel implements WritableByteChannel, ReadableByteChannel {
  private ByteBuffer data;
  private boolean empty = true;
  private boolean transfering = true;

  public DummyChannel() {
    empty = true;
    data = ByteBuffer.allocate(4096);
  }

  @Override
  public int write(ByteBuffer src) throws IOException {
    if (!data.hasRemaining()) {
      try {
        sleep(100);
      } catch (Exception e) {
        throw new IOException(e);
      }
    }

    int written;
    transfering = true;
    synchronized (this) {
      if (src.remaining() < data.remaining()) {
        written = src.remaining();
        data.put(src);
      } else {
        written = data.remaining();
        int oldlimit = src.limit();
        int newlimit = src.position() + data.remaining();
        src.limit(newlimit);
        data.put(src);
        src.limit(oldlimit);
      }
      empty = false;
    }
    return written;
  }

  @Override
  public int read(ByteBuffer dst) throws IOException {
    if (empty) {
      if (!transfering) return -1;
      else {
        try {
          sleep(100);
        } catch (Exception e) {
          e.printStackTrace();
        }
        return 0;
      }
    }

    int read;
    synchronized (this) {
      data.flip();
      if (dst.remaining() > data.remaining()) {
        read = data.remaining();
        while (data.hasRemaining()) {
          dst.put(data);
        }
        data.clear();
        empty = true;
      } else {
        read = dst.remaining();
        int oldlimit = data.limit();
        int newlimit = data.position() + dst.remaining();
        data.limit(newlimit);
        dst.put(data);
        data.limit(oldlimit);
      }

    }
    return read;
  }

  @Override
  public void close() throws IOException {
    transfering = false;
  }

  @Override
  public boolean isOpen() {
    return true;
  }
}
