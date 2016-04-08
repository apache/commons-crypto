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
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Properties;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

import com.intel.chimera.cipher.Cipher;
import com.intel.chimera.cipher.CipherFactory;
import com.intel.chimera.stream.input.Input;
import com.intel.chimera.utils.IOUtils;
import com.intel.chimera.utils.Utils;

import static com.intel.chimera.cipher.CipherTransformation.AES_CTR_NOPADDING;

/**
 * PositionedCryptoInputStream provides the capability to decrypt the stream starting
 * at random position as well as provides the foundation for positioned read for
 * decrypting. This needs a stream cipher mode such as AES CTR mode.
 */
public class PositionedCryptoInputStream extends CTRCryptoInputStream {

  /**
   * DirectBuffer pool
   */
  private final Queue<ByteBuffer> bufferPool = new
      ConcurrentLinkedQueue<ByteBuffer>();

  /**
   * Cipher pool
   */
  private final Queue<CipherState> cipherPool = new
      ConcurrentLinkedQueue<CipherState>();

  public PositionedCryptoInputStream(Properties props, Input in,
      byte[] key, byte[] iv, long streamOffset) throws IOException {
    this(in, Utils.getCipherInstance(AES_CTR_NOPADDING, props),
        Utils.getBufferSize(props), key, iv, streamOffset);
  }

  public PositionedCryptoInputStream(
      Input input,
      Cipher cipher,
      int bufferSize,
      byte[] key,
      byte[] iv,
      long streamOffset) throws IOException {
    super(input, cipher, bufferSize, key, iv, streamOffset);
  }

  /**
   * Read upto the specified number of bytes from a given position
   * within a stream and return the number of bytes read. This does not
   * change the current offset of the stream, and is thread-safe.
   */
  public int read(long position, byte[] buffer, int offset, int length)
      throws IOException {
    checkStream();
    final int n = input.read(position, buffer, offset, length);
    if (n > 0) {
      // This operation does not change the current offset of the file
      decrypt(position, buffer, offset, n);
    }
    return n;
  }

  /**
   * Read the specified number of bytes from a given position within a stream.
   * This does not change the current offset of the stream and is thread-safe.
   */
  public void readFully(long position, byte[] buffer, int offset, int length)
      throws IOException {
    checkStream();
    IOUtils.readFully(input, position, buffer, offset, length);
    if (length > 0) {
      // This operation does not change the current offset of the file
      decrypt(position, buffer, offset, length);
    }
  }

  public void readFully(long position, byte[] buffer) throws IOException {
    readFully(position, buffer, 0, buffer.length);
  }

  /**
   * Decrypt length bytes in buffer starting at offset. Output is also put
   * into buffer starting at offset. It is thread-safe.
   */
  protected void decrypt(long position, byte[] buffer, int offset, int length)
      throws IOException {
    ByteBuffer inBuffer = getBuffer();
    ByteBuffer outBuffer = getBuffer();
    CipherState state = null;
    try {
      state = getCipherState();
      byte[] iv = getInitIV().clone();
      resetCipher(state, position, iv);
      byte padding = getPadding(position);
      inBuffer.position(padding); // Set proper position for input data.

      int n = 0;
      while (n < length) {
        int toDecrypt = Math.min(length - n, inBuffer.remaining());
        inBuffer.put(buffer, offset + n, toDecrypt);

        // Do decryption
        decrypt(state, inBuffer, outBuffer, padding);

        outBuffer.get(buffer, offset + n, toDecrypt);
        n += toDecrypt;
        padding = postDecryption(state, inBuffer, position + n, iv);
      }
    } finally {
      returnBuffer(inBuffer);
      returnBuffer(outBuffer);
      returnCipherState(state);
    }
  }

  /**
   * Do the decryption using inBuffer as input and outBuffer as output.
   * Upon return, inBuffer is cleared; the decrypted data starts at
   * outBuffer.position() and ends at outBuffer.limit();
   */
  private void decrypt(CipherState state, ByteBuffer inBuffer,
      ByteBuffer outBuffer, byte padding) throws IOException {
    Utils.checkState(inBuffer.position() >= padding);
    if(inBuffer.position() == padding) {
      // There is no real data in inBuffer.
      return;
    }
    inBuffer.flip();
    outBuffer.clear();
    decryptBuffer(state, inBuffer, outBuffer);
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

  private void decryptBuffer(CipherState state, ByteBuffer inBuffer, ByteBuffer outBuffer)
      throws IOException {
    int inputSize = inBuffer.remaining();
    try {
      int n = state.getCipher().update(inBuffer, outBuffer);
      if (n < inputSize) {
        /**
         * Typically code will not get here. Cipher#update will consume all
         * input data and put result in outBuffer.
         * Cipher#doFinal will reset the cipher context.
         */
        state.getCipher().doFinal(inBuffer, outBuffer);
        state.reset(true);
      }
    } catch (ShortBufferException e) {
      throw new IOException(e);
    } catch (IllegalBlockSizeException e) {
      throw new IOException(e);
    } catch (BadPaddingException e) {
      throw new IOException(e);
    }
  }

  /**
   * This method is executed immediately after decryption. Check whether
   * cipher should be updated and recalculate padding if needed.
   */
  private byte postDecryption(CipherState state, ByteBuffer inBuffer,
      long position, byte[] iv) throws IOException {
    byte padding = 0;
    if (state.isReset()) {
      /*
       * This code is generally not executed since the cipher usually
       * maintains cipher context (e.g. the counter) internally. However,
       * some implementations can't maintain context so a re-init is necessary
       * after each decryption call.
       */
      resetCipher(state, position, iv);
      padding = getPadding(position);
      inBuffer.position(padding);
    }
    return padding;
  }

  /** Calculate the counter and iv, reset the cipher. */
  private void resetCipher(CipherState state, long position, byte[] iv)
      throws IOException {
    final long counter = getCounter(position);
    Utils.calculateIV(getInitIV(), counter, iv);
    try {
      state.getCipher().init(Cipher.DECRYPT_MODE, getKey(), iv);
    } catch (InvalidKeyException e) {
      throw new IOException(e);
    } catch (InvalidAlgorithmParameterException e) {
      throw new IOException(e);
    }
    state.reset(false);
  }

  /** Get Cipher from pool */
  private CipherState getCipherState() throws IOException {
    CipherState state = cipherPool.poll();
    if (state == null) {
      Cipher cipher;
      try {
        cipher = CipherFactory.getInstance(getCipher().getTransformation(),
            getCipher().getProperties());
      } catch (GeneralSecurityException e) {
        throw new IOException(e);
      }
      state = new CipherState(cipher);
    }

    return state;
  }

  /** Return Cipher to pool */
  private void returnCipherState(CipherState state) {
    if (state != null) {
      cipherPool.add(state);
    }
  }

  /** Get direct buffer from pool */
  private ByteBuffer getBuffer() {
    ByteBuffer buffer = bufferPool.poll();
    if (buffer == null) {
      buffer = ByteBuffer.allocateDirect(getBufferSize());
    }

    return buffer;
  }

  /** Return direct buffer to pool */
  private void returnBuffer(ByteBuffer buf) {
    if (buf != null) {
      buf.clear();
      bufferPool.add(buf);
    }
  }

  @Override
  public void close() throws IOException {
    if (!isOpen()) {
      return;
    }

    cleanBufferPool();
    super.close();
  }

  /** Clean direct buffer pool */
  private void cleanBufferPool() {
    ByteBuffer buf;
    while ((buf = bufferPool.poll()) != null) {
      Utils.freeDirectBuffer(buf);
    }
  }

  private class CipherState {
    private Cipher cipher;
    private boolean reset;

    public CipherState(Cipher cipher) {
      this.cipher = cipher;
      this.reset = false;
    }

    public Cipher getCipher() {
      return cipher;
    }

    public boolean isReset() {
      return reset;
    }

    public void reset(boolean reset) {
      this.reset = reset;
    }
  }
}
