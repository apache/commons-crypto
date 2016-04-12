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
package com.intel.chimera.stream.output;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;

/**
 * The StreamOutput class takes a <code>OutputStream</code> object and wraps it as 
 * <code>Output</code> object acceptable by <code>CryptoOutputStream</code> as the output target.
 */
public class StreamOutput implements Output {
  private byte[] buf;
  private int bufferSize;
  protected OutputStream out;

  /**
   * Constructs a {@link com.intel.chimera.stream.output.StreamOutput}.
   *
   * @param out the OutputStream object.
   * @param bufferSize the buffersize.
   */
  public StreamOutput(OutputStream out, int bufferSize) {
    this.out = out;
    this.bufferSize = bufferSize;
  }

  /**
   * Overrides the {@link com.intel.chimera.stream.output.Output#write(ByteBuffer)}.
   * Writes a sequence of bytes to this output from the given buffer.
   *
   * @param  src
   *         The buffer from which bytes are to be retrieved.
   *
   * @return The number of bytes written, possibly zero.
   * @throws IOException if an I/O error occurs.
   */
  @Override
  public int write(ByteBuffer src) throws IOException {
    final int len = src.remaining();
    final byte[] buf = getBuf();
    
    int remaining = len;
    while(remaining > 0) {
      final int n = Math.min(remaining, bufferSize);
      src.get(buf, 0, n);
      out.write(buf, 0, n);
      remaining = src.remaining();
    }
    
    return len;
  }

  /**
   * Overrides the {@link Output#flush()}.
   * Flushes this output and forces any buffered output bytes
   * to be written out if the under layer output method support.
   *
   * @throws IOException if an I/O error occurs.
   */
  @Override
  public void flush() throws IOException {
    out.flush();
  }

  /**
   * Overrides the {@link Output#close()}.
   * Closes this output and releases any system resources associated
   * with the under layer output.
   *
   * @throws IOException if an I/O error occurs.
   */
  @Override
  public void close() throws IOException {
    out.close();
  }
  
  private byte[] getBuf() {
    if (buf == null) {
      buf = new byte[bufferSize];
    }
    return buf;
  }

}
