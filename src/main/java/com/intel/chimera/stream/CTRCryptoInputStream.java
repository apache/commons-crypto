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
 * CTRCryptoInputStream decrypts data. AES CTR mode is required in order to
 * ensure that the plain text and cipher text have a 1:1 mapping. CTR crypto
 * stream has stream characteristic which is useful for implement features
 * like random seek. The decryption is buffer based. The key points of the
 * decryption are (1) calculating the counter and (2) padding through stream
 * position:
 * <p/>
 * counter = base + pos/(algorithm blocksize);
 * padding = pos%(algorithm blocksize);
 * <p/>
 * The underlying stream offset is maintained as state. It is not thread-safe.
 */
public class CTRCryptoInputStream extends CryptoInputStream {
  /**
   * Underlying stream offset
   */
  protected long streamOffset = 0;

  /**
   * Padding = pos%(algorithm blocksize); Padding is put into {@link #inBuffer}
   * before any other data goes in. The purpose of padding is to put the input
   * data at proper position.
   */
  private byte padding;

  /**
   * Flag to mark whether the cipher has been reset
   */
  private boolean cipherReset = false;

  public CTRCryptoInputStream(Properties props, InputStream in,
      byte[] key, byte[] iv)
      throws IOException {
    this(props, in, key, iv, 0);
  }

  public CTRCryptoInputStream(Properties props, ReadableByteChannel in,
      byte[] key, byte[] iv)
      throws IOException {
    this(props, in, key, iv, 0);
  }

  public CTRCryptoInputStream(InputStream in, Cipher cipher, int bufferSize,
      byte[] key, byte[] iv) throws IOException {
    this(in, cipher, bufferSize, key, iv, 0);
  }

  public CTRCryptoInputStream(ReadableByteChannel in, Cipher cipher,
      int bufferSize, byte[] key, byte[] iv) throws IOException {
    this(in, cipher, bufferSize, key, iv, 0);
  }

  public CTRCryptoInputStream(
      Input input,
      Cipher cipher,
      int bufferSize,
      byte[] key,
      byte[] iv) throws IOException {
    this(input, cipher, bufferSize, key, iv, 0);
  }

  public CTRCryptoInputStream(Properties props, InputStream in,
      byte[] key, byte[] iv, long streamOffset)
      throws IOException {
    this(in, Utils.getCipherInstance(CipherTransformation.AES_CTR_NOPADDING, props),
        Utils.getBufferSize(props), key, iv, streamOffset);
  }

  public CTRCryptoInputStream(Properties props, ReadableByteChannel in,
      byte[] key, byte[] iv, long streamOffset)
      throws IOException {
    this(in, Utils.getCipherInstance(CipherTransformation.AES_CTR_NOPADDING, props),
        Utils.getBufferSize(props), key, iv, streamOffset);
  }

  public CTRCryptoInputStream(InputStream in, Cipher cipher, int bufferSize,
      byte[] key, byte[] iv, long streamOffset) throws IOException {
    this(new StreamInput(in, bufferSize), cipher, bufferSize, key, iv, streamOffset);
  }

  public CTRCryptoInputStream(ReadableByteChannel in, Cipher cipher,
      int bufferSize, byte[] key, byte[] iv, long streamOffset) throws IOException {
    this(new ChannelInput(in), cipher, bufferSize, key, iv, streamOffset);
  }

  public CTRCryptoInputStream(
      Input input,
      Cipher cipher,
      int bufferSize,
      byte[] key,
      byte[] iv,
      long streamOffset) throws IOException {
    super(input, cipher, bufferSize, key, iv);

    Utils.checkStreamCipher(cipher);

    resetStreamOffset(streamOffset);
  }

  /** Skip n bytes */
  @Override
  public long skip(long n) throws IOException {
    Utils.checkArgument(n >= 0, "Negative skip length.");
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
    int unread = outBuffer.remaining();
    if (unread <= 0) { // Fill the unread decrypted data buffer firstly
      final int n = input.read(inBuffer);
      if (n <= 0) {
        return n;
      }

      streamOffset += n; // Read n bytes
      if (buf.isDirect() && buf.remaining() >= inBuffer.position() && padding == 0) {
        // Use buf as the output buffer directly
        decryptInPlace(buf);
        padding = postDecryption(streamOffset);
        return n;
      } else {
        // Use outBuffer as the output buffer
        decrypt();
        padding = postDecryption(streamOffset);
      }
    }

    // Copy decrypted data from outBuffer to buf
    unread = outBuffer.remaining();
    final int toRead = buf.remaining();
    if (toRead <= unread) {
      final int limit = outBuffer.limit();
      outBuffer.limit(outBuffer.position() + toRead);
      buf.put(outBuffer);
      outBuffer.limit(limit);
      return toRead;
    } else {
      buf.put(outBuffer);
      return unread;
    }
  }

  /**
   * Seek the stream to a specific position relative to start of the under layer stream.
   * 
   * @param position The position to seek to
   * @throws IOException if seek failed
   */
  public void seek(long position) throws IOException {
    Utils.checkArgument(position >= 0, "Cannot seek to negative offset.");
    checkStream();
    /*
     * If data of target pos in the underlying stream has already been read
     * and decrypted in outBuffer, we just need to re-position outBuffer.
     */
    if (position >= getStreamPosition() && position <= getStreamOffset()) {
      int forward = (int) (position - getStreamPosition());
      if (forward > 0) {
        outBuffer.position(outBuffer.position() + forward);
      }
    } else {
      input.seek(position);
      resetStreamOffset(position);
    }
  }

  protected long getStreamOffset() {
    return streamOffset;
  }

  protected long getStreamPosition() {
    return streamOffset - outBuffer.remaining();
  }

  /**
   * Decrypt more data by reading the under layer stream. The decrypted data will
   * be put in the output buffer.
   *
   * @return The number of decrypted data. -1 if end of the decrypted stream
   */
  protected int decryptMore() throws IOException {
    int n = input.read(inBuffer);
    if (n <= 0) {
      return n;
    }

    streamOffset += n; // Read n bytes
    decrypt();
    padding = postDecryption(streamOffset);
    return outBuffer.remaining();
  }

  /**
   * Do the decryption using inBuffer as input and outBuffer as output.
   * Upon return, inBuffer is cleared; the decrypted data starts at
   * outBuffer.position() and ends at outBuffer.limit();
   */
  protected void decrypt() throws IOException {
    Utils.checkState(inBuffer.position() >= padding);
    if(inBuffer.position() == padding) {
      // There is no real data in inBuffer.
      return;
    }

    inBuffer.flip();
    outBuffer.clear();
    decryptBuffer(outBuffer);
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
   * Do the decryption using inBuffer as input and buf as output.
   * Upon return, inBuffer is cleared; the buf's position will be equal to
   * <i>p</i>&nbsp;<tt>+</tt>&nbsp;<i>n</i> where <i>p</i> is the position before
   * decryption, <i>n</i> is the number of bytes decrypted.
   * The buf's limit will not have changed.
   */
  protected void decryptInPlace(ByteBuffer buf) throws IOException {
    Utils.checkState(inBuffer.position() >= padding);
    Utils.checkState(buf.isDirect());
    Utils.checkState(buf.remaining() >= inBuffer.position());
    Utils.checkState(padding == 0);

    if(inBuffer.position() == padding) {
      // There is no real data in inBuffer.
      return;
    }
    inBuffer.flip();
    decryptBuffer(buf);
    inBuffer.clear();
  }

  /**
   * Decrypt all data in buf: total n bytes from given start position.
   * Output is also buf and same start position.
   * buf.position() and buf.limit() should be unchanged after decryption.
   */
  protected void decrypt(ByteBuffer buf, int offset, int len)
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
        decrypt();
        buf.position(offset + n);
        buf.limit(limit);
        n += outBuffer.remaining();
        buf.put(outBuffer);
      } finally {
        padding = postDecryption(streamOffset - (len - n));
      }
    }
    buf.position(pos);
  }

  /**
   * This method is executed immediately after decryption. Check whether
   * cipher should be updated and recalculate padding if needed.
   */
  protected byte postDecryption(long position) throws IOException {
    byte padding = 0;
    if (cipherReset) {
      /*
       * This code is generally not executed since the cipher usually
       * maintains cipher context (e.g. the counter) internally. However,
       * some implementations can't maintain context so a re-init is necessary
       * after each decryption call.
       */
      resetCipher(position);
      padding = getPadding(position);
      inBuffer.position(padding);
    }
    return padding;
  }

  protected long getCounter(long position) {
    return position / cipher.getTransformation().getAlgorithmBlockSize();
  }

  protected byte getPadding(long position) {
    return (byte)(position % cipher.getTransformation().getAlgorithmBlockSize());
  }

  /** Initialize the cipher. */
  @Override
  protected void initCipher() {
    // Do nothing for initCipher
    // Will reset the cipher when reset the stream offset
  }

  /** Calculate the counter and iv, reset the cipher. */
  protected void resetCipher(long position)
      throws IOException {
    final long counter = getCounter(position);
    Utils.calculateIV(initIV, counter, iv);
    try {
      cipher.init(Cipher.DECRYPT_MODE, key, iv);
    } catch (InvalidKeyException e) {
      throw new IOException(e);
    } catch (InvalidAlgorithmParameterException e) {
      throw new IOException(e);
    }
    cipherReset = false;
  }

  /**
   * Reset the underlying stream offset; clear {@link #inBuffer} and
   * {@link #outBuffer}. This Typically happens during {@link #skip(long)}.
   */
  protected void resetStreamOffset(long offset) throws IOException {
    streamOffset = offset;
    inBuffer.clear();
    outBuffer.clear();
    outBuffer.limit(0);
    resetCipher(offset);
    padding = getPadding(offset);
    inBuffer.position(padding); // Set proper position for input data.
  }

  protected void decryptBuffer(ByteBuffer out)
      throws IOException {
    int inputSize = inBuffer.remaining();
    try {
      int n = cipher.update(inBuffer, out);
      if (n < inputSize) {
        /**
         * Typically code will not get here. Cipher#update will consume all
         * input data and put result in outBuffer.
         * Cipher#doFinal will reset the cipher context.
         */
        cipher.doFinal(inBuffer, out);
        cipherReset = true;
      }
    } catch (ShortBufferException e) {
      throw new IOException(e);
    } catch (IllegalBlockSizeException e) {
      throw new IOException(e);
    } catch (BadPaddingException e) {
      throw new IOException(e);
    }
  }

}
