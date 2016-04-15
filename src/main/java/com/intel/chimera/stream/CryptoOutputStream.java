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
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.Channel;
import java.nio.channels.WritableByteChannel;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

import com.intel.chimera.cipher.Cipher;
import com.intel.chimera.cipher.CipherTransformation;
import com.intel.chimera.stream.output.ChannelOutput;
import com.intel.chimera.stream.output.Output;
import com.intel.chimera.stream.output.StreamOutput;
import com.intel.chimera.utils.Utils;

/**
 * CryptoOutputStream encrypts data and writes to the under layer output. It supports
 * any mode of operations such as AES CBC/CTR/GCM mode in concept. It is not thread-safe.
 */

public class CryptoOutputStream extends OutputStream implements
    WritableByteChannel {
  private final byte[] oneByteBuf = new byte[1];

  /** The output.*/
  protected Output output;

  /**the Cipher instance*/
  protected final Cipher cipher;

  /**The buffer size.*/
  protected final int bufferSize;

  /**Crypto key for the cipher.*/
  protected final byte[] key;

  /**The initial IV.*/
  protected final byte[] initIV;

  /** Initialization vector for the cipher.*/
  protected byte[] iv;

  /** Flag to mark whether the output stream is closed.*/
  protected boolean closed;

  /**
   * Input data buffer. The data starts at inBuffer.position() and ends at
   * inBuffer.limit().
   */
  protected ByteBuffer inBuffer;

  /**
   * Encrypted data buffer. The data starts at outBuffer.position() and ends at
   * outBuffer.limit().
   */
  protected ByteBuffer outBuffer;

  /**
   * Constructs a {@link com.intel.chimera.stream.CryptoOutputStream}.
   *
   * @param transformation the CipherTransformation instance.
   * @param props The <code>Properties</code> class represents a set of
   *              properties.
   * @param out the output stream.
   * @param key crypto key for the cipher.
   * @param iv Initialization vector for the cipher.
   * @throws IOException if an I/O error occurs.
   */
  public CryptoOutputStream(CipherTransformation transformation,
      Properties props, OutputStream out, byte[] key, byte[] iv)
      throws IOException {
    this(out, Utils.getCipherInstance(transformation, props),
        Utils.getBufferSize(props), key, iv);
  }

  /**
   * Constructs a {@link com.intel.chimera.stream.CryptoOutputStream}.
   *
   * @param transformation the CipherTransformation instance.
   * @param props The <code>Properties</code> class represents a set of
   *              properties.
   * @param out the WritableByteChannel instance.
   * @param key crypto key for the cipher.
   * @param iv Initialization vector for the cipher.
   * @throws IOException if an I/O error occurs.
   */
  public CryptoOutputStream(CipherTransformation transformation,
      Properties props, WritableByteChannel out, byte[] key, byte[] iv)
      throws IOException {
    this(out, Utils.getCipherInstance(transformation, props),
        Utils.getBufferSize(props), key, iv);
  }

  /**
   * Constructs a {@link com.intel.chimera.stream.CryptoOutputStream}.
   *
   * @param out the output stream.
   * @param cipher the Cipher instance.
   * @param bufferSize the bufferSize.
   * @param key crypto key for the cipher.
   * @param iv Initialization vector for the cipher.
   * @throws IOException if an I/O error occurs.
   */
  public CryptoOutputStream(OutputStream out, Cipher cipher,
      int bufferSize, byte[] key, byte[] iv) throws IOException {
    this(new StreamOutput(out, bufferSize), cipher, bufferSize, key, iv);
  }

  /**
   * Constructs a {@link com.intel.chimera.stream.CryptoOutputStream}.
   *
   * @param channel the WritableByteChannel instance.
   * @param cipher the cipher instance.
   * @param bufferSize the bufferSize.
   * @param key crypto key for the cipher.
   * @param iv Initialization vector for the cipher.
   * @throws IOException if an I/O error occurs.
   */
  public CryptoOutputStream(WritableByteChannel channel, Cipher cipher,
      int bufferSize, byte[] key, byte[] iv) throws IOException {
    this(new ChannelOutput(channel), cipher, bufferSize, key, iv);
  }

  /**
   * Constructs a {@link com.intel.chimera.stream.CryptoOutputStream}.
   *
   * @param output the output stream.
   * @param cipher the Cipher instance.
   * @param bufferSize the bufferSize.
   * @param key crypto key for the cipher.
   * @param iv Initialization vector for the cipher.
   * @throws IOException if an I/O error occurs.
   */
  protected CryptoOutputStream(Output output, Cipher cipher,
      int bufferSize, byte[] key, byte[] iv)
      throws IOException {

    this.output = output;
    this.bufferSize = Utils.checkBufferSize(cipher, bufferSize);
    this.cipher = cipher;
    this.key = key.clone();
    this.initIV = iv.clone();
    this.iv = iv.clone();
    inBuffer = ByteBuffer.allocateDirect(this.bufferSize);
    outBuffer = ByteBuffer.allocateDirect(this.bufferSize +
        cipher.getTransformation().getAlgorithmBlockSize());

    initCipher();
  }

  /**
   * Overrides the {@link java.io.OutputStream#write(byte[])}.
   * Writes the specified byte to this output stream.
   *
   * @param b the data.
   * @throws IOException if an I/O error occurs.
   */
  @Override
  public void write(int b) throws IOException {
    oneByteBuf[0] = (byte) (b & 0xff);
    write(oneByteBuf, 0, oneByteBuf.length);
  }

  /**
   * Overrides the {@link java.io.OutputStream#write(byte[], int, int)}.
   * Encryption is buffer based.
   * If there is enough room in {@link #inBuffer}, then write to this buffer.
   * If {@link #inBuffer} is full, then do encryption and write data to the
   * underlying stream.
   *
   * @param b the data.
   * @param off the start offset in the data.
   * @param len the number of bytes to write.
   * @throws IOException if an I/O error occurs.
   */
  public void write(byte[] b, int off, int len) throws IOException {
    checkStream();
    if (b == null) {
      throw new NullPointerException();
    } else if (off < 0 || len < 0 || off > b.length ||
        len > b.length - off) {
      throw new IndexOutOfBoundsException();
    }

    while (len > 0) {
      final int remaining = inBuffer.remaining();
      if (len < remaining) {
        inBuffer.put(b, off, len);
        len = 0;
      } else {
        inBuffer.put(b, off, remaining);
        off += remaining;
        len -= remaining;
        encrypt();
      }
    }
  }

  /**
   * Overrides the {@link OutputStream#flush()}.
   * To flush, we need to encrypt the data in the buffer and write to the
   * underlying stream, then do the flush.
   *
   * @throws IOException if an I/O error occurs.
   */
  @Override
  public void flush() throws IOException {
    checkStream();
    encrypt();
    output.flush();
    super.flush();
  }

  /**
   * Overrides the {@link OutputStream#close()}.
   * Closes this output stream and releases any system resources
   * associated with this stream.
   *
   * @throws IOException if an I/O error occurs.
   */
  @Override
  public void close() throws IOException {
    if (closed) {
      return;
    }

    try {
      encryptFinal();
      output.close();
      freeBuffers();
      cipher.close();
      super.close();
    } finally {
      closed = true;
    }
  }

  /**
   * Overrides the {@link Channel#isOpen()}.
   * Tells whether or not this channel is open.
   *
   * @return <tt>true</tt> if, and only if, this channel is open
   */
  @Override
  public boolean isOpen() {
    return !closed;
  }

  /**
   * Overrides the {@link java.nio.channels.WritableByteChannel#write(ByteBuffer)}.
   * Writes a sequence of bytes to this channel from the given buffer.
   *
   * @param src The buffer from which bytes are to be retrieved.
   * @return The number of bytes written, possibly zero.
   * @throws IOException if an I/O error occurs.
   */
  @Override
  public int write(ByteBuffer src) throws IOException {
    checkStream();
    final int len = src.remaining();
    int remaining = len;
    while (remaining > 0) {
      final int space = inBuffer.remaining();
      if (remaining < space) {
        inBuffer.put(src);
        remaining = 0;
      } else {
        // to void copy twice, we set the limit to copy directly
        final int oldLimit = src.limit();
        final int newLimit = src.position() + space;
        src.limit(newLimit);

        inBuffer.put(src);

        // restore the old limit
        src.limit(oldLimit);

        remaining -= space;
        encrypt();
      }
    }

    return len;
  }

  /**
   * Initializes the cipher.
   *
   * @throws IOException if an I/O error occurs.
   */
  protected void initCipher()
      throws IOException {
    try {
      cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    } catch (InvalidKeyException e) {
      throw new IOException(e);
    } catch(InvalidAlgorithmParameterException e) {
      throw new IOException(e);
    }
  }

  /**
   * Does the encryption, input is {@link #inBuffer} and output is
   * {@link #outBuffer}.
   *
   *@throws IOException if an I/O error occurs.
   */
  protected void encrypt() throws IOException {

    inBuffer.flip();
    outBuffer.clear();

    try {
      cipher.update(inBuffer, outBuffer);
    } catch (ShortBufferException e) {
      throw new IOException(e);
    }

    inBuffer.clear();
    outBuffer.flip();

    // write to output
    output.write(outBuffer);
  }

  /**
   * Does final encryption of the last data.
   *
   * @throws IOException if an I/O error occurs.
   */
  protected void encryptFinal() throws IOException {
    inBuffer.flip();
    outBuffer.clear();

    try {
      cipher.doFinal(inBuffer, outBuffer);
    } catch (ShortBufferException e) {
      throw new IOException(e);
    } catch (IllegalBlockSizeException e) {
      throw new IOException(e);
    } catch( BadPaddingException e) {
      throw new IOException(e);
    }

    inBuffer.clear();
    outBuffer.flip();

    // write to output
    output.write(outBuffer);
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
