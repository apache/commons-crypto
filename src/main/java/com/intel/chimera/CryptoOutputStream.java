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
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.WritableByteChannel;
import java.util.Properties;

import com.google.common.base.Preconditions;
import com.intel.chimera.crypto.Cipher;
import com.intel.chimera.output.ChannelOutput;
import com.intel.chimera.output.Output;
import com.intel.chimera.output.StreamOutput;
import com.intel.chimera.utils.Utils;

/**
 * CryptoOutputStream encrypts data. It is not thread-safe. AES CTR mode is
 * required in order to ensure that the plain text and cipher text have a 1:1
 * mapping. The encryption is buffer based. The key points of the encryption are
 * (1) calculating counter and (2) padding through stream position.
 * <p/>
 * counter = base + pos/(algorithm blocksize); 
 * padding = pos%(algorithm blocksize); 
 * <p/>
 * The underlying stream offset is maintained as state.
 */
public class CryptoOutputStream extends OutputStream implements
    WritableByteChannel {
  private Output output;
  private final Cipher cipher;
  private final int bufferSize;
  
  private final byte[] key;
  private final byte[] initIV;
  private byte[] iv;
  
  private long streamOffset = 0; // Underlying stream offset.
  private boolean cipherReset = false;
   
  private final byte[] oneByteBuf = new byte[1];
  
  /**
   * Input data buffer. The data starts at inBuffer.position() and ends at 
   * inBuffer.limit().
   */
  private ByteBuffer inBuffer;
  
  /**
   * Encrypted data buffer. The data starts at outBuffer.position() and ends at 
   * outBuffer.limit();
   */
  private ByteBuffer outBuffer;
  
  /**
   * Padding = pos%(algorithm blocksize); Padding is put into {@link #inBuffer} 
   * before any other data goes in. The purpose of padding is to put input data
   * at proper position.
   */
  private byte padding;
  private boolean closed;

  public CryptoOutputStream(Properties props, OutputStream out,
      byte[] key, byte[] iv) throws IOException {
    this(out, Utils.getCipherInstance(props), Utils.getBufferSize(props), key, iv);
  }
  
  public CryptoOutputStream(Properties props, WritableByteChannel out,
      byte[] key, byte[] iv) throws IOException {
    this(out, Utils.getCipherInstance(props), Utils.getBufferSize(props), key, iv);
  }

  public CryptoOutputStream(OutputStream out, Cipher cipher, 
      int bufferSize, byte[] key, byte[] iv) throws IOException {
    this(new StreamOutput(out, bufferSize), cipher, bufferSize, key, iv);
  }

  public CryptoOutputStream(WritableByteChannel channel, Cipher cipher, 
      int bufferSize, byte[] key, byte[] iv) throws IOException {
    this(new ChannelOutput(channel), cipher, bufferSize, key, iv);
  }

  public CryptoOutputStream(Output output, Cipher cipher, 
      int bufferSize, byte[] key, byte[] iv) 
      throws IOException {
    Utils.checkStreamCipher(cipher);
    
    this.output = output;
    this.bufferSize = Utils.checkBufferSize(cipher, bufferSize);
    this.cipher = cipher;
    this.key = key.clone();
    this.initIV = iv.clone();
    this.iv = iv.clone();
    inBuffer = ByteBuffer.allocateDirect(this.bufferSize);
    outBuffer = ByteBuffer.allocateDirect(this.bufferSize);
    this.streamOffset = 0;
    
    resetCipher();
  }
  
  /**
   * Encryption is buffer based.
   * If there is enough room in {@link #inBuffer}, then write to this buffer.
   * If {@link #inBuffer} is full, then do encryption and write data to the
   * underlying stream.
   * @param b the data.
   * @param off the start offset in the data.
   * @param len the number of bytes to write.
   * @throws IOException
   */
  @Override
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
  
  @Override
  public void close() throws IOException {
    if (closed) {
      return;
    }
    
    try {
      encrypt();
      output.close();
      freeBuffers();
      super.close();
    } finally {
      closed = true;
    }
  }
  
  /**
   * To flush, we need to encrypt the data in the buffer and write to the 
   * underlying stream, then do the flush.
   */
  @Override
  public void flush() throws IOException {
    checkStream();
    encrypt();
    output.flush();
    super.flush();
  }
  
  @Override
  public void write(int b) throws IOException {
    oneByteBuf[0] = (byte)(b & 0xff);
    write(oneByteBuf, 0, oneByteBuf.length);
  }
  
  @Override
  public boolean isOpen() {
    return !closed;
  }

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
   * Do the encryption, input is {@link #inBuffer} and output is 
   * {@link #outBuffer}.
   */
  private void encrypt() throws IOException {
    Preconditions.checkState(inBuffer.position() >= padding);
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
  
  /** Reset the {@link #Cipher}: calculate counter and {@link #padding}. */
  private void resetCipher() throws IOException {
    final long counter =
        streamOffset / cipher.getTransformation().getAlgorithmBlockSize();
    padding =
        (byte)(streamOffset % cipher.getTransformation().getAlgorithmBlockSize());
    inBuffer.position(padding); // Set proper position for input data.
    
    Utils.calculateIV(initIV, counter, iv);
    cipher.init(Cipher.ENCRYPT_MODE, key, iv);
    cipherReset = false;
  }
  
  private void encryptBuffer(ByteBuffer out)
  		throws IOException {
  	int inputSize = inBuffer.remaining();
  	int n = cipher.update(inBuffer, out);
  	if (n < inputSize) {
			/**
			 * Typically code will not get here. Cipher#update will consume all 
			 * input data and put result in outBuffer. 
			 * Cipher#doFinal will reset the cipher context.
			 */
			cipher.doFinal(inBuffer, outBuffer);
			cipherReset = true;
		}
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
}
