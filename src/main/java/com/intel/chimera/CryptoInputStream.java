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
package com.intel.chimera;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.security.GeneralSecurityException;
import java.util.Properties;

import com.google.common.base.Preconditions;
import com.intel.chimera.input.ChannelInput;
import com.intel.chimera.input.Input;
import com.intel.chimera.input.StreamInput;
import com.intel.chimera.utils.Utils;

/**
 * CryptoInputStream decrypts data. It is not thread-safe. AES CTR mode is
 * required in order to ensure that the plain text and cipher text have a 1:1
 * mapping. The decryption is buffer based. The key points of the decryption
 * are (1) calculating the counter and (2) padding through stream position:
 * <p/>
 * counter = base + pos/(algorithm blocksize); 
 * padding = pos%(algorithm blocksize); 
 * <p/>
 * The underlying stream offset is maintained as state.
 */
public class CryptoInputStream extends InputStream implements 
    ReadableByteChannel {
  private final byte[] oneByteBuf = new byte[1];
  private final CryptoCodec codec;
  private final Decryptor decryptor;
  private final int bufferSize;
  
  /**
   * Input data buffer. The data starts at inBuffer.position() and ends at 
   * to inBuffer.limit().
   */
  private ByteBuffer inBuffer;
  
  /**
   * The decrypted data buffer. The data starts at outBuffer.position() and 
   * ends at outBuffer.limit();
   */
  private ByteBuffer outBuffer;
  private long streamOffset = 0; // Underlying stream offset.
  
  /**
   * Padding = pos%(algorithm blocksize); Padding is put into {@link #inBuffer} 
   * before any other data goes in. The purpose of padding is to put the input 
   * data at proper position.
   */
  private byte padding;
  private boolean closed;
  private final byte[] key;
  private final byte[] initIV;
  private byte[] iv;
  private Input input;
  
  public CryptoInputStream(Properties props, InputStream in,
      byte[] key, byte[] iv) throws IOException {
    this(in, CryptoCodec.getInstance(props), Utils.getBufferSize(props), key, iv);
  }

  public CryptoInputStream(Properties props, ReadableByteChannel in,
      byte[] key, byte[] iv) throws IOException {
    this(in, CryptoCodec.getInstance(props), Utils.getBufferSize(props), key, iv);
  }

  public CryptoInputStream(InputStream in, CryptoCodec codec, 
      int bufferSize, byte[] key, byte[] iv) throws IOException {
    this(new StreamInput(in, bufferSize), codec, bufferSize, key, iv, 0);
  }

  public CryptoInputStream(ReadableByteChannel in, CryptoCodec codec, 
      int bufferSize, byte[] key, byte[] iv) throws IOException {
    this(new ChannelInput(in), codec, bufferSize, key, iv, 0);
  }

  public CryptoInputStream(
      Input input,
      CryptoCodec codec,
      int bufferSize,
      byte[] key,
      byte[] iv,
      long streamOffset) throws IOException {
    Utils.checkCodec(codec);

    this.input = input;
    this.codec = codec;
    this.bufferSize = Utils.checkBufferSize(codec, bufferSize);
    this.key = key.clone();
    this.initIV = iv.clone();
    this.iv = iv.clone();
    this.streamOffset = streamOffset;

    inBuffer = ByteBuffer.allocateDirect(this.bufferSize);
    outBuffer = ByteBuffer.allocateDirect(this.bufferSize);
    decryptor = getDecryptor();
    resetStreamOffset(streamOffset);
  }

  /**
   * Decryption is buffer based.
   * If there is data in {@link #outBuffer}, then read it out of this buffer.
   * If there is no data in {@link #outBuffer}, then read more from the 
   * underlying stream and do the decryption.
   * @param b the buffer into which the decrypted data is read.
   * @param off the buffer offset.
   * @param len the maximum number of decrypted data bytes to read.
   * @return int the total number of decrypted data bytes read into the buffer.
   * @throws IOException
   */
  @Override
  public int read(byte[] b, int off, int len) throws IOException {
    checkStream();
    if (b == null) {
      throw new NullPointerException();
    } else if (off < 0 || len < 0 || len > b.length - off) {
      throw new IndexOutOfBoundsException();
    } else if (len == 0) {
      return 0;
    }
    
    final int remaining = outBuffer.remaining();
    if (remaining > 0) {
      int n = Math.min(len, remaining);
      outBuffer.get(b, off, n);
      return n;
    } else {
      int n = input.read(inBuffer);
      if (n <= 0) {
        return n;
      }
      
      streamOffset += n; // Read n bytes
      decrypt(decryptor, inBuffer, outBuffer, padding);
      padding = afterDecryption(decryptor, inBuffer, streamOffset, iv);
      n = Math.min(len, outBuffer.remaining());
      outBuffer.get(b, off, n);
      return n;
    }
  }
  
  /**
   * Do the decryption using inBuffer as input and outBuffer as output.
   * Upon return, inBuffer is cleared; the decrypted data starts at 
   * outBuffer.position() and ends at outBuffer.limit();
   */
  private void decrypt(Decryptor decryptor, ByteBuffer inBuffer, 
      ByteBuffer outBuffer, byte padding) throws IOException {
    Preconditions.checkState(inBuffer.position() >= padding);
    if(inBuffer.position() == padding) {
      // There is no real data in inBuffer.
      return;
    }
    inBuffer.flip();
    outBuffer.clear();
    decryptor.decrypt(inBuffer, outBuffer);
    inBuffer.clear();
    outBuffer.flip();
    if (padding > 0) {
      /*
       * The plain text and cipher text have a 1:1 mapping, they start at the 
       * same position.
       */
      outBuffer.position(padding);
    }
  }
  
  /**
   * This method is executed immediately after decryption. Check whether 
   * decryptor should be updated and recalculate padding if needed. 
   */
  private byte afterDecryption(Decryptor decryptor, ByteBuffer inBuffer, 
      long position, byte[] iv) throws IOException {
    byte padding = 0;
    if (decryptor.isContextReset()) {
      /*
       * This code is generally not executed since the decryptor usually 
       * maintains decryption context (e.g. the counter) internally. However, 
       * some implementations can't maintain context so a re-init is necessary 
       * after each decryption call.
       */
      updateDecryptor(decryptor, position, iv);
      padding = getPadding(position);
      inBuffer.position(padding);
    }
    return padding;
  }
  
  private long getCounter(long position) {
    return position / codec.getCipherSuite().getAlgorithmBlockSize();
  }
  
  private byte getPadding(long position) {
    return (byte)(position % codec.getCipherSuite().getAlgorithmBlockSize());
  }
  
  /** Calculate the counter and iv, update the decryptor. */
  private void updateDecryptor(Decryptor decryptor, long position, byte[] iv) 
      throws IOException {
    final long counter = getCounter(position);
    codec.calculateIV(initIV, counter, iv);
    decryptor.init(key, iv);
  }
  
  /**
   * Reset the underlying stream offset; clear {@link #inBuffer} and 
   * {@link #outBuffer}. This Typically happens during {@link #seek(long)} 
   * or {@link #skip(long)}.
   */
  private void resetStreamOffset(long offset) throws IOException {
    streamOffset = offset;
    inBuffer.clear();
    outBuffer.clear();
    outBuffer.limit(0);
    updateDecryptor(decryptor, offset, iv);
    padding = getPadding(offset);
    inBuffer.position(padding); // Set proper position for input data.
  }
  
  @Override
  public void close() throws IOException {
    if (closed) {
      return;
    }
    
    input.close();
    freeBuffers();
    closed = true;
  }

  /** Skip n bytes */
  @Override
  public long skip(long n) throws IOException {
    Preconditions.checkArgument(n >= 0, "Negative skip length.");
    checkStream();
    
    if (n == 0) {
      return 0;
    } else if (n <= outBuffer.remaining()) {
      int pos = outBuffer.position() + (int) n;
      outBuffer.position(pos);
      return n;
    } else {
      /*
       * Subtract outBuffer.remaining() to see how many bytes we need to 
       * skip in the underlying stream. Add outBuffer.remaining() to the 
       * actual number of skipped bytes in the underlying stream to get the 
       * number of skipped bytes from the user's point of view.
       */
      n -= outBuffer.remaining();
      long skipped = input.skip(n);
      if (skipped < 0) {
        skipped = 0;
      }
      long pos = streamOffset + skipped;
      skipped += outBuffer.remaining();
      resetStreamOffset(pos);
      return skipped;
    }
  }

  /** ByteBuffer read. */
  @Override
  public int read(ByteBuffer buf) throws IOException {
    checkStream();
    final int unread = outBuffer.remaining();
    if (unread > 0) { // Have unread decrypted data in buffer.
      int toRead = buf.remaining();
      if (toRead <= unread) {
        final int limit = outBuffer.limit();
        outBuffer.limit(outBuffer.position() + toRead);
        buf.put(outBuffer);
        outBuffer.limit(limit);
        return toRead;
      } else {
        buf.put(outBuffer);
      }
    }

    final int pos = buf.position();
    final int n = input.read(buf);
    if (n > 0) {
      streamOffset += n; // Read n bytes
      decrypt(buf, pos, n);
    }

    if (n >= 0) {
      return unread + n;
    } else {
      if (unread == 0) {
        return -1;
      } else {
        return unread;
      }
    }
  }

  /**
   * Decrypt all data in buf: total n bytes from given start position.
   * Output is also buf and same start position.
   * buf.position() and buf.limit() should be unchanged after decryption.
   */
  private void decrypt(ByteBuffer buf, int offset, int len) 
      throws IOException {
    final int pos = buf.position();
    final int limit = buf.limit();
    int n = 0;
    while (n < len) {
      buf.position(offset + n);
      buf.limit(offset + n + Math.min(len - n, inBuffer.remaining()));
      inBuffer.put(buf);
      // Do decryption
      try {
        decrypt(decryptor, inBuffer, outBuffer, padding);
        buf.position(offset + n);
        buf.limit(limit);
        n += outBuffer.remaining();
        buf.put(outBuffer);
      } finally {
        padding = afterDecryption(decryptor, inBuffer, streamOffset - (len - n), iv);
      }
    }
    buf.position(pos);
  }
  
  @Override
  public int available() throws IOException {
    checkStream();
    
    return input.available() + outBuffer.remaining();
  }

  @Override
  public boolean markSupported() {
    return false;
  }
  
  @Override
  public void mark(int readLimit) {
  }
  
  @Override
  public void reset() throws IOException {
    throw new IOException("Mark/reset not supported");
  }

  @Override
  public int read() throws IOException {
    return (read(oneByteBuf, 0, 1) == -1) ? -1 : (oneByteBuf[0] & 0xff);
  }
  
  private void checkStream() throws IOException {
    if (closed) {
      throw new IOException("Stream closed");
    }
  }

  /** Forcibly free the direct buffers. */
  private void freeBuffers() {
    Utils.freeDB(inBuffer);
    Utils.freeDB(outBuffer);
  }

  /** Get decryptor from pool */
  private Decryptor getDecryptor() throws IOException {
    try {
      return codec.createDecryptor();
    } catch (GeneralSecurityException e) {
      throw new IOException(e);
    }
  }

  @Override
  public boolean isOpen() {
    return !closed;
  }
}

