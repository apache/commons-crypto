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
package com.intel.chimera.stream;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Properties;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

import com.intel.chimera.cipher.Cipher;
import com.intel.chimera.cipher.CipherTransformation;
import com.intel.chimera.stream.input.ChannelInput;
import com.intel.chimera.stream.input.Input;
import com.intel.chimera.stream.input.StreamInput;
import com.intel.chimera.utils.Utils;

/**
 * CryptoInputStream reads input data and decrypts data in stream manner. It supports
 * any mode of operations such as AES CBC/CTR/GCM mode in concept.It is not thread-safe.
 *
 */

public class CryptoInputStream extends InputStream implements
    ReadableByteChannel {
  private final byte[] oneByteBuf = new byte[1];

  protected final Cipher cipher;
  protected final int bufferSize;

  protected final byte[] key;
  protected final byte[] initIV;
  protected byte[] iv;

  protected boolean closed;
  protected boolean finalDone = false;

  protected Input input;

  /**
   * Input data buffer. The data starts at inBuffer.position() and ends at
   * to inBuffer.limit().
   */
  protected ByteBuffer inBuffer;

  /**
   * The decrypted data buffer. The data starts at outBuffer.position() and
   * ends at outBuffer.limit();
   */
  protected ByteBuffer outBuffer;

  public CryptoInputStream(CipherTransformation transformation,
      Properties props, InputStream in, byte[] key, byte[] iv)
      throws IOException {
    this(in, Utils.getCipherInstance(transformation, props),
        Utils.getBufferSize(props), key, iv);
  }

  public CryptoInputStream(CipherTransformation transformation,
      Properties props, ReadableByteChannel in, byte[] key, byte[] iv)
      throws IOException {
    this(in, Utils.getCipherInstance(transformation, props),
        Utils.getBufferSize(props), key, iv);
  }

  public CryptoInputStream(InputStream in, Cipher cipher, int bufferSize,
      byte[] key, byte[] iv) throws IOException {
    this(new StreamInput(in, bufferSize), cipher, bufferSize, key, iv);
  }

  public CryptoInputStream(ReadableByteChannel in, Cipher cipher,
      int bufferSize, byte[] key, byte[] iv) throws IOException {
    this(new ChannelInput(in), cipher, bufferSize, key, iv);
  }

  public CryptoInputStream(
      Input input,
      Cipher cipher,
      int bufferSize,
      byte[] key,
      byte[] iv) throws IOException {
    this.input = input;
    this.cipher = cipher;
    this.bufferSize = Utils.checkBufferSize(cipher, bufferSize);
    this.key = key.clone();
    this.initIV = iv.clone();
    this.iv = iv.clone();

    inBuffer = ByteBuffer.allocateDirect(this.bufferSize);
    outBuffer = ByteBuffer.allocateDirect(this.bufferSize +
        cipher.getTransformation().getAlgorithmBlockSize());
    outBuffer.limit(0);

    initCipher();
  }

  @Override
  public int read() throws IOException {
    int n;
    while ((n = read(oneByteBuf, 0, 1)) == 0) ;
    return (n == -1) ? -1 : oneByteBuf[0] & 0xff;
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

    int remaining = outBuffer.remaining();
    if (remaining > 0) {
      // Satisfy the read with the existing data
      int n = Math.min(len, remaining);
      outBuffer.get(b, off, n);
      return n;
    } else {
      // No data in the out buffer, try read new data and decrypt it
      int nd = decryptMore();
      if(nd <= 0)
        return nd;

      int n = Math.min(len, outBuffer.remaining());
      outBuffer.get(b, off, n);
      return n;
    }
  }

  @Override
  public long skip(long n) throws IOException {
    Utils.checkArgument(n >= 0, "Negative skip length.");
    checkStream();

    if (n == 0) {
      return 0;
    }

    long remaining = n;
    int nd;

    while (remaining > 0) {
      if(remaining <= outBuffer.remaining()) {
        // Skip in the remaining buffer
        int pos = outBuffer.position() + (int) remaining;
        outBuffer.position(pos);

        remaining = 0;
        break;
      } else {
        remaining -= outBuffer.remaining();
        outBuffer.clear();
      }

      nd = decryptMore();
      if (nd < 0) {
        break;
      }
    }

    return n - remaining;
  }

  @Override
  public int available() throws IOException {
    checkStream();

    return input.available() + outBuffer.remaining();
  }

  @Override
  public void close() throws IOException {
    if (closed) {
      return;
    }

    input.close();
    freeBuffers();
    cipher.close();
    super.close();
    closed = true;
  }

  @Override
  public void mark(int readlimit) {
  }

  @Override
  public void reset() throws IOException {
    throw new IOException("Mark/reset not supported");
  }

  @Override
  public boolean markSupported() {
    return false;
  }

  @Override
  public boolean isOpen() {
    return !closed;
  }

  @Override
  public int read(ByteBuffer dst) throws IOException {
    checkStream();
    int remaining = outBuffer.remaining();
    if (remaining <= 0) {
      // Decrypt more data
      int nd = decryptMore();
      if(nd < 0) {
        return -1;
      }
    }

    // Copy decrypted data from outBuffer to dst
    remaining = outBuffer.remaining();
    final int toRead = dst.remaining();
    if (toRead <= remaining) {
      final int limit = outBuffer.limit();
      outBuffer.limit(outBuffer.position() + toRead);
      dst.put(outBuffer);
      outBuffer.limit(limit);
      return toRead;
    } else {
      dst.put(outBuffer);
      return remaining;
    }
  }

  /**
   * Get the buffer size
   */
  protected int getBufferSize() {
    return bufferSize;
  }

  /**
   * Get the key
   */
  protected byte[] getKey() {
    return key;
  }

  /**
   * Get the initialization vector
   */
  protected byte[] getInitIV() {
    return initIV;
  }

  /**
   * Get the internal Cipher
   */
  protected Cipher getCipher() {
    return cipher;
  }

  /** Initialize the cipher. */
  protected void initCipher()
      throws IOException {
    try {
      cipher.init(Cipher.DECRYPT_MODE, key, iv);
    } catch (InvalidKeyException e) {
      throw new IOException(e);
    } catch(InvalidAlgorithmParameterException e) {
      throw new IOException(e);
    }
  }

  /**
   * Decrypt more data by reading the under layer stream. The decrypted data will
   * be put in the output buffer. If the end of the under stream reached, we will
   * do final of the cipher to finish all the decrypting of data.
   *
   * @return The number of decrypted data. -1 if end of the decrypted stream
   */
  protected int decryptMore() throws IOException {
    if(finalDone) {
      return -1;
    }

    int n = input.read(inBuffer);
    if (n < 0) {
      // The stream is end, finalize the cipher stream
      decryptFinal();

      // Satisfy the read with the remaining
      int remaining = outBuffer.remaining();
      if (remaining > 0) {
        return remaining;
      }

      // End of the stream
      return -1;
    } else if(n == 0) {
      // No data is read, but the stream is not end yet
      return 0;
    } else {
      decrypt();
      return outBuffer.remaining();
    }
  }

  /**
   * Do the decryption using inBuffer as input and outBuffer as output.
   * Upon return, inBuffer is cleared; the decrypted data starts at
   * outBuffer.position() and ends at outBuffer.limit();
   */
  protected void decrypt() throws IOException {
    // Prepare the input buffer and clear the out buffer
    inBuffer.flip();
    outBuffer.clear();

    try {
      cipher.update(inBuffer, outBuffer);
    } catch (ShortBufferException e) {
      throw new IOException(e);
    }

    // Clear the input buffer and prepare out buffer
    inBuffer.clear();
    outBuffer.flip();
  }

  /**
   * Do final of the cipher to end the decrypting stream
   */
  protected void decryptFinal() throws IOException {
    // Prepare the input buffer and clear the out buffer
    inBuffer.flip();
    outBuffer.clear();

    try {
      cipher.doFinal(inBuffer, outBuffer);
      finalDone = true;
    } catch (ShortBufferException e) {
      throw new IOException(e);
    } catch (IllegalBlockSizeException e) {
      throw new IOException(e);
    } catch( BadPaddingException e) {
      throw new IOException(e);
    }

    // Clear the input buffer and prepare out buffer
    inBuffer.clear();
    outBuffer.flip();
  }

  protected void checkStream() throws IOException {
    if (closed) {
      throw new IOException("Stream closed");
    }
  }

  /** Forcibly free the direct buffers. */
  protected void freeBuffers() {
    Utils.freeDirectBuffer(inBuffer);
    Utils.freeDirectBuffer(outBuffer);
  }
}