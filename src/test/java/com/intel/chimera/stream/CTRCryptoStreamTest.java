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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.channels.Channels;

import com.intel.chimera.cipher.Cipher;
import com.intel.chimera.cipher.CipherTransformation;

public class CTRCryptoStreamTest extends AbstractCryptoStreamTest {

  public void setUp() throws IOException {
    transformation = CipherTransformation
        .AES_CTR_NOPADDING;
  }

  @Override
  protected CTRCryptoInputStream getCryptoInputStream
      (ByteArrayInputStream bais, Cipher cipher, int
      bufferSize,byte[] iv, boolean withChannel)
      throws IOException {
    if (withChannel) {
      return new CTRCryptoInputStream(Channels.newChannel(bais), cipher,
          bufferSize, key, iv);
    } else {
      return new CTRCryptoInputStream(bais, cipher, bufferSize, key, iv);
    }
  }

  @Override
  protected CTRCryptoOutputStream getCryptoOutputStream(ByteArrayOutputStream baos,Cipher cipher, int
      bufferSize,  byte[] iv, boolean withChannel)
      throws IOException {
    if (withChannel) {
      return new CTRCryptoOutputStream(Channels.newChannel(baos), cipher, bufferSize, key, iv);
    } else {
      return new CTRCryptoOutputStream(baos, cipher, bufferSize, key, iv);
    }
  }
}
