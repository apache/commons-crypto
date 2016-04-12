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
import java.nio.ByteBuffer;

/**
 * The Output interface abstract the output target of <code>CryptoOutputStream</code> so that
 * different implementation of output can be used. The implementation Output interface will usually
 * wraps an output mechanism such as <code>OutputStream</code> or <code>WritableByteChannel</code>.
 */
public interface Output {

  /**
   * Writes a sequence of bytes to this output from the given buffer.
   *
   * <p> An attempt is made to write up to <i>r</i> bytes to the channel,
   * where <i>r</i> is the number of bytes remaining in the buffer, that is,
   * <tt>src.remaining()</tt>, at the moment this method is invoked.
   *
   * <p> Suppose that a byte sequence of length <i>n</i> is written, where
   * <tt>0</tt>&nbsp;<tt>&lt;=</tt>&nbsp;<i>n</i>&nbsp;<tt>&lt;=</tt>&nbsp;<i>r</i>.
   * This byte sequence will be transferred from the buffer starting at index
   * <i>p</i>, where <i>p</i> is the buffer's position at the moment this
   * method is invoked; the index of the last byte written will be
   * <i>p</i>&nbsp;<tt>+</tt>&nbsp;<i>n</i>&nbsp;<tt>-</tt>&nbsp;<tt>1</tt>.
   * Upon return the buffer's position will be equal to
   * <i>p</i>&nbsp;<tt>+</tt>&nbsp;<i>n</i>; its limit will not have changed.
   *
   * @param  src
   *         The buffer from which bytes are to be retrieved.
   *
   * @return The number of bytes written, possibly zero.
   *
   * @throws  IOException
   *          If some other I/O error occurs.
   */
  int write(ByteBuffer src) throws IOException;
  
  /**
   * Flushes this output and forces any buffered output bytes
   * to be written out if the under layer output method support.
   * The general contract of <code>flush</code> is
   * that calling it is an indication that, if any bytes previously
   * written have been buffered by the implementation of the output
   * stream, such bytes should immediately be written to their
   * intended destination.
   *
   * @throws IOException  if an I/O error occurs.
   */
  void flush() throws IOException;
  
  /**
   * Closes this output and releases any system resources associated
   * with the under layer output.
   *
   * @throws IOException  if an I/O error occurs.
   */
  void close() throws IOException;
}
