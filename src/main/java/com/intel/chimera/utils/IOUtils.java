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
package com.intel.chimera.utils;

import java.io.IOException;
import java.io.InputStream;

import com.intel.chimera.stream.input.Input;
import org.apache.commons.logging.Log;

/**
 * General utility methods for working with IO.
 */
public class IOUtils {

  private IOUtils() {}

  /**
   * Does the readFully based on the Input read.
   *
   * @param in the input stream of bytes.
   * @param buf the buffer to be read.
   * @param off the start offset in array buffer.
   * @param len the maximum number of bytes to read.
   * @throws IOException if an I/O error occurs.
   */
  public static void readFully(InputStream in, byte buf[],
      int off, int len) throws IOException {
    int toRead = len;
    while (toRead > 0) {
      int ret = in.read(buf, off, toRead);
      if (ret < 0) {
        throw new IOException( "Premature EOF from inputStream");
      }
      toRead -= ret;
      off += ret;
    }
  }

  /**
   * Does the readFully based on Input's positioned read.
   * This does not change the current offset of the stream and is thread-safe.
   *
   * @param in the input source.
   * @param position the given position.
   * @param buffer the buffer to be read.
   * @param length the maximum number of bytes to read.
   * @param offset the start offset in array buffer.
   * @throws IOException if an I/O error occurs.
   */
  public static void readFully(Input in, long position,
      byte[] buffer, int offset, int length) throws IOException {
    int nread = 0;
    while (nread < length) {
      int nbytes = in.read(position+nread, buffer, offset+nread, length-nread);
      if (nbytes < 0) {
        throw new IOException("End of stream reached before reading fully.");
      }
      nread += nbytes;
    }
  }

  /**
   * Closes the Closeable objects and <b>ignore</b> any {@link IOException} or
   * null pointers. Must only be used for cleanup in exception handlers.
   *
   * @param log the log to record problems to at debug level. Can be null.
   * @param closeables the objects to close.
   */
  public static void cleanup(Log log, java.io.Closeable... closeables) {
    for (java.io.Closeable c : closeables) {
      if (c != null) {
        try {
          c.close();
        } catch(Throwable e) {
          if (log != null && log.isDebugEnabled()) {
            log.debug("Exception in closing " + c, e);
          }
        }
      }
    }
  }
}
