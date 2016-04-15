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
import java.nio.channels.Channel;
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

  /**The Cipher instance.*/
  protected final Cipher cipher;

  /**The buffer size.*/
  protected final int bufferSize;

  /**Crypto key for the cipher.*/
  protected final byte[] key;

  /**The initial IV.*/
  protected final byte[] initIV;

  /** Initialization vector for the cipher.*/
  protected byte[] iv;

  /** Flag to mark whether the input stream is closed.*/
  protected boolean closed;

  /** Flag to mark whether do final of the cipher to end the decrypting stream.*/
  protected boolean finalDone = false;

  /**The input data.*/
  protected Input input;

  /**
   * Input data buffer. The data starts at inBuffer.position() and ends at
   * to inBuffer.limit().
   */
  protected ByteBuffer inBuffer;

  /**
   * The decrypted data buffer. The data starts at outBuffer.position() and
   * ends at outBuffer.limit().
   */
  protected ByteBuffer outBuffer;

  /**
   * Constructs a {@link com.intel.chimera.stream.CryptoInputStream}.
   *
   * @param transformation the CipherTransformation instance.
   * @param props The <code>Properties</code> class represents a set of
   *              properties.
   * @param in the input stream.
   * @param key crypto key for the cipher.
   * @param iv Initialization vector for the cipher.
   * @throws IOException if an I/O error occurs.
   */
  public CryptoInputStream(CipherTransformation transformation,
      Properties props, InputStream in, byte[] key, byte[] iv)
      throws IOException {
    this(in, Utils.getCipherInstance(transformation, props),
        Utils.getBufferSize(props), key, iv);
  }

  /**
   * Constructs a {@link com.intel.chimera.stream.CryptoInputStream}.
   *
   * @param transformation the CipherTransformation instance.
   * @param props The <code>Properties</code> class represents a set of
   *              properties.
   * @param in the ReadableByteChannel object.
   * @param key crypto key for the cipher.
   * @param iv Initialization vector for the cipher.
   * @throws IOException if an I/O error occurs.
   */
  public CryptoInputStream(CipherTransformation transformation,
      Properties props, ReadableByteChannel in, byte[] key, byte[] iv)
      throws IOException {
    this(in, Utils.getCipherInstance(transformation, props),
        Utils.getBufferSize(props), key, iv);
  }

  /**
   * Constructs a {@link com.intel.chimera.stream.CryptoInputStream}.
   *
   * @param cipher the cipher instance.
   * @param in the input stream.
   * @param bufferSize the bufferSize.
   * @param key crypto key for the cipher.
   * @param iv Initialization vector for the cipher.
   * @throws IOException if an I/O error occurs.
   */
  public CryptoInputStream(InputStream in, Cipher cipher, int bufferSize,
      byte[] key, byte[] iv) throws IOException {
    this(new StreamInput(in, bufferSize), cipher, bufferSize, key, iv);
  }

  /**
   * Constructs a {@link com.intel.chimera.stream.CryptoInputStream}.
   *
   * @param in the ReadableByteChannel instance.
   * @param cipher the cipher instance.
   * @param bufferSize the bufferSize.
   * @param key crypto key for the cipher.
   * @param iv Initialization vector for the cipher.
   * @throws IOException if an I/O error occurs.
   */
  public CryptoInputStream(ReadableByteChannel in, Cipher cipher,
      int bufferSize, byte[] key, byte[] iv) throws IOException {
    this(new ChannelInput(in), cipher, bufferSize, key, iv);
  }

  /**
   * Constructs a {@link com.intel.chimera.stream.CryptoInputStream}.
   *
   * @param input the input data.
   * @param cipher the cipher instance.
   * @param bufferSize the bufferSize.
   * @param key crypto key for the cipher.
   * @param iv Initialization vector for the cipher.
   * @throws IOException if an I/O error occurs.
   */
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

  /**
   * Overrides the {@link java.io.InputStream#read()}.
   * Reads the next byte of data from the input stream.
   *
   * @return the next byte of data, or <code>-1</code> if the end of the
   *         stream is reached.
   * @throws IOException if an I/O error occurs.
   */
  @Override
  public int read() throws IOException {
    int n;
    while ((n = read(oneByteBuf, 0, 1)) == 0) ;
    return (n == -1) ? -1 : oneByteBuf[0] & 0xff;
  }

  /**
   * Overrides the {@link java.io.InputStream#read(byte[], int, int)}.
   * Decryption is buffer based.
   * If there is data in {@link #outBuffer}, then read it out of this buffer.
   * If there is no data in {@link #outBuffer}, then read more from the
   * underlying stream and do the decryption.
   *
   * @param b the buffer into which the decrypted data is read.
   * @param off the buffer offset.
   * @param len the maximum number of decrypted data bytes to read.
   * @return int the total number of decrypted data bytes read into the buffer.
   * @throws IOException if an I/O error occurs.
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

  /**
   * Overrides the {@link java.io.InputStream#skip(long)}.
   * Skips over and discards <code>n</code> bytes of data from this input
   * stream.
   *
   * @param n the number of bytes to be skipped.
   * @return the actual number of bytes skipped.
   * @throws IOException if an I/O error occurs.
   */
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

  /**
   * Overrides the {@link InputStream#available()}.
   * Returns an estimate of the number of bytes that can be read (or
   * skipped over) from this input stream without blocking by the next
   * invocation of a method for this input stream.
   *
   * @return an estimate of the number of bytes that can be read (or skipped
   *         over) from this input stream without blocking or {@code 0} when
   *          it reaches the end of the input stream.
   * @throws IOException if an I/O error occurs.
   */
  @Override
  public int available() throws IOException {
    checkStream();

    return input.available() + outBuffer.remaining();
  }

  /**
   * Overrides the {@link InputStream#close()}.
   * Closes this input stream and releases any system resources associated
   * with the stream.
   *
   * @throws IOException if an I/O error occurs.
   */
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

  /**
   * Overrides the {@link java.io.InputStream#mark(int)}.
   * For {@link CryptoInputStream},we don't support the mark method.
   *
   * @param readlimit the maximum limit of bytes that can be read before
   *                  the mark position becomes invalid.
   */
  @Override
  public void mark(int readlimit) {
  }

  /**
   * Overrides the {@link InputStream#reset()}.
   * For {@link CryptoInputStream},we don't support the reset method.
   *
   * @throws IOException if an I/O error occurs.
   */
  @Override
  public void reset() throws IOException {
    throw new IOException("Mark/reset not supported");
  }

  /**
   * Overrides the {@link InputStream#markSupported()}.
   *
   * @return false,the {@link CTRCryptoInputStream} don't support the mark method.
   */
  @Override
  public boolean markSupported() {
    return false;
  }

  /**
   * Overrides the {@link Channel#isOpen()}.
   *
   * @return <tt>true</tt> if, and only if, this channel is open.
   */
  @Override
  public boolean isOpen() {
    return !closed;
  }

  /**
   * Overrides the {@link java.nio.channels.ReadableByteChannel#read(ByteBuffer)}.
   * Reads a sequence of bytes from this channel into the given buffer.
   *
   * @param dst The buffer into which bytes are to be transferred.
   * @return The number of bytes read, possibly zero, or <tt>-1</tt> if the
   *         channel has reached end-of-stream.
   * @throws IOException if an I/O error occurs.
   */
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
   * Gets the buffer size.
   *
   * @return the bufferSize.
   */
  protected int getBufferSize() {
    return bufferSize;
  }

  /**
   * Gets the key.
   *
   * @return the key.
   */
  protected byte[] getKey() {
    return key;
  }

  /**
   * Gets the initialization vector.
   *
   * @return the initIV.
   */
  protected byte[] getInitIV() {
    return initIV;
  }

  /**
   * Gets the internal Cipher.
   *
   * @return the cipher instance.
   */
  protected Cipher getCipher() {
    return cipher;
  }

  /**
   * Initializes the cipher.
   *
   * @throws IOException if an I/O error occurs.
   */
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
   * Decrypts more data by reading the under layer stream. The decrypted data will
   * be put in the output buffer. If the end of the under stream reached, we will
   * do final of the cipher to finish all the decrypting of data.
   *
   * @return The number of decrypted data. -1 if end of the decrypted stream.
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
   * Does the decryption using inBuffer as input and outBuffer as output.
   * Upon return, inBuffer is cleared; the decrypted data starts at
   * outBuffer.position() and ends at outBuffer.limit().
   *
   * @throws IOException if an I/O error occurs.
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
   * Does final of the cipher to end the decrypting stream.
   *
   *@throws IOException if an I/O error occurs.
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

  /**
   * Checks whether the stream is closed.
   *
   * @throws IOException if an I/O error occurs.
   */
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