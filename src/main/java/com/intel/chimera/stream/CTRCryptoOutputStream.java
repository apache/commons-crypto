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
import java.nio.channels.WritableByteChannel;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

import com.intel.chimera.cipher.Cipher;
import com.intel.chimera.cipher.CipherTransformation;
import com.intel.chimera.output.ChannelOutput;
import com.intel.chimera.output.Output;
import com.intel.chimera.output.StreamOutput;
import com.intel.chimera.utils.Utils;

/**
 * CTRCryptoOutputStream encrypts data. It is not thread-safe. AES CTR mode is
 * required in order to ensure that the plain text and cipher text have a 1:1
 * mapping. The encryption is buffer based. The key points of the encryption are
 * (1) calculating counter and (2) padding through stream position.
 * <p/>
 * counter = base + pos/(algorithm blocksize);
 * padding = pos%(algorithm blocksize);
 * <p/>
 * The underlying stream offset is maintained as state.
 */
public class CTRCryptoOutputStream extends CryptoOutputStream {
  /**
   * Underlying stream offset.
   */
  protected long streamOffset = 0;

  /**
   * Padding = pos%(algorithm blocksize); Padding is put into {@link #inBuffer}
   * before any other data goes in. The purpose of padding is to put input data
   * at proper position.
   */
  private byte padding;

  /**
   * Flag to mark whether the cipher has been reset
   */
  private boolean cipherReset = false;

  public CTRCryptoOutputStream(Properties props, OutputStream out,
      byte[] key, byte[] iv)
      throws IOException {
    this(props, out, key, iv, 0);
  }

  public CTRCryptoOutputStream(Properties props, WritableByteChannel out,
      byte[] key, byte[] iv)
      throws IOException {
    this(props, out, key, iv, 0);
  }

  public CTRCryptoOutputStream(OutputStream out, Cipher cipher,
      int bufferSize, byte[] key, byte[] iv) throws IOException {
    this(out, cipher, bufferSize, key, iv, 0);
  }

  public CTRCryptoOutputStream(WritableByteChannel channel, Cipher cipher,
      int bufferSize, byte[] key, byte[] iv) throws IOException {
    this(channel, cipher, bufferSize, key, iv, 0);
  }

  public CTRCryptoOutputStream(Output output, Cipher cipher,
      int bufferSize, byte[] key, byte[] iv)
      throws IOException {
    this(output, cipher, bufferSize, key, iv, 0);
  }

  public CTRCryptoOutputStream(Properties props, OutputStream out,
      byte[] key, byte[] iv, long streamOffset)
      throws IOException {
    this(out, Utils.getCipherInstance(CipherTransformation.AES_CTR_NOPADDING, props),
        Utils.getBufferSize(props), key, iv, streamOffset);
  }

  public CTRCryptoOutputStream(Properties props, WritableByteChannel out,
      byte[] key, byte[] iv, long streamOffset)
      throws IOException {
    this(out, Utils.getCipherInstance(CipherTransformation.AES_CTR_NOPADDING, props),
        Utils.getBufferSize(props), key, iv, streamOffset);
  }

  public CTRCryptoOutputStream(OutputStream out, Cipher cipher,
      int bufferSize, byte[] key, byte[] iv, long streamOffset) throws IOException {
    this(new StreamOutput(out, bufferSize), cipher,
        bufferSize, key, iv, streamOffset);
  }

  public CTRCryptoOutputStream(WritableByteChannel channel, Cipher cipher,
      int bufferSize, byte[] key, byte[] iv, long streamOffset) throws IOException {
    this(new ChannelOutput(channel), cipher,
        bufferSize, key, iv, streamOffset);
  }

  public CTRCryptoOutputStream(Output output, Cipher cipher,
      int bufferSize, byte[] key, byte[] iv, long streamOffset)
      throws IOException {
    super(output, cipher, bufferSize, key, iv);

    Utils.checkStreamCipher(cipher);
    this.streamOffset = streamOffset;

    resetCipher();
  }

  /**
   * Do the encryption, input is {@link #inBuffer} and output is
   * {@link #outBuffer}.
   */
  @Override
  protected void encrypt() throws IOException {
    Utils.checkState(inBuffer.position() >= padding);
    if (inBuffer.position() == padding) {
      // There is no real data in the inBuffer.
      return;
    }

    inBuffer.flip();
    outBuffer.clear();
    encryptBuffer(outBuffer);
    inBuffer.clear();
    outBuffer.flip();

    if (padding > 0) {
      /*
       * The plain text and cipher text have a 1:1 mapping, they start at the
       * same position.
       */
      outBuffer.position(padding);
      padding = 0;
    }

    final int len = output.write(outBuffer);
    streamOffset += len;
    if (cipherReset) {
      /*
       * This code is generally not executed since the encryptor usually
       * maintains encryption context (e.g. the counter) internally. However,
       * some implementations can't maintain context so a re-init is necessary
       * after each encryption call.
       */
      resetCipher();
    }
  }

  /**
   * Do final encryption of the last data
   */
  @Override
  protected void encryptFinal() throws IOException {
    // The same as the normal encryption for Counter mode
    encrypt();
  }

  /** Initialize the cipher. */
  @Override
  protected void initCipher() {
    // Do nothing for initCipher
    // Will reset the cipher considering the stream offset
  }

  /** Reset the {@link #cipher}: calculate counter and {@link #padding}. */
  private void resetCipher() throws IOException {
    final long counter =
        streamOffset / cipher.getTransformation().getAlgorithmBlockSize();
    padding =
        (byte)(streamOffset % cipher.getTransformation().getAlgorithmBlockSize());
    inBuffer.position(padding); // Set proper position for input data.

    Utils.calculateIV(initIV, counter, iv);
    try {
      cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    } catch (InvalidKeyException e) {
      throw new IOException(e);
    }catch (InvalidAlgorithmParameterException e) {
      throw new IOException(e);
    }
    cipherReset = false;
  }

  private void encryptBuffer(ByteBuffer out)
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
    } catch (BadPaddingException e) {
      throw new IOException(e);
    } catch (IllegalBlockSizeException e) {
      throw new IOException(e);
    }
  }
}
