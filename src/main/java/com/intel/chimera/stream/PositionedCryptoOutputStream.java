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
import java.nio.channels.WritableByteChannel;
import java.util.Properties;

import com.intel.chimera.cipher.Cipher;
import com.intel.chimera.cipher.CipherTransformation;
import com.intel.chimera.output.ChannelOutput;
import com.intel.chimera.output.Output;
import com.intel.chimera.output.StreamOutput;
import com.intel.chimera.utils.Utils;

import static com.intel.chimera.cipher.CipherTransformation.AES_CTR_NOPADDING;

/**
 * PositionedCryptoOutputStream provides the capability to append to an
 * existing crypto stream from a specific start point.
 * This needs a stream cipher mode such as AES CTR mode.
 */
public class PositionedCryptoOutputStream extends CTRCryptoOutputStream {
  public PositionedCryptoOutputStream(Properties props, OutputStream out,
      byte[] key, byte[] iv, long streamOffset) throws IOException {
    this(out, Utils.getCipherInstance(AES_CTR_NOPADDING, props),
        Utils.getBufferSize(props), key, iv, streamOffset);
  }

  public PositionedCryptoOutputStream(Properties props, WritableByteChannel out,
      byte[] key, byte[] iv,
      long streamOffset) throws IOException {
    this(out, Utils.getCipherInstance(AES_CTR_NOPADDING, props),
        Utils.getBufferSize(props), key, iv, streamOffset);
  }

  public PositionedCryptoOutputStream(OutputStream out, Cipher cipher,
      int bufferSize, byte[] key, byte[] iv, long streamOffset) throws IOException {
    this(new StreamOutput(out, bufferSize), cipher, bufferSize, key, iv, streamOffset);
  }

  public PositionedCryptoOutputStream(WritableByteChannel channel, Cipher cipher,
      int bufferSize, byte[] key, byte[] iv, long streamOffset) throws IOException {
    this(new ChannelOutput(channel), cipher, bufferSize, key, iv, streamOffset);
  }

  public PositionedCryptoOutputStream(Output output, Cipher cipher,
      int bufferSize, byte[] key, byte[] iv, long streamOffset)
      throws IOException {
    super(output, cipher, bufferSize, key, iv, streamOffset);
    Utils.checkStreamCipher(cipher);
  }
}
