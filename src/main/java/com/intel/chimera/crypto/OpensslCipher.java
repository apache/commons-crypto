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
package com.intel.chimera.crypto;

import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Properties;
import java.util.Random;

import com.google.common.base.Preconditions;
import com.intel.chimera.utils.Utils;

/**
 * Implement the Cipher using JNI into OpenSSL.
 */
public class OpensslCipher extends Cipher {
	private final CipherTransformation transformation;
  private final Openssl cipher;
  private final Random random;
  
  public OpensslCipher(Properties props, CipherTransformation transformation)
  		throws GeneralSecurityException {
  	this.transformation = transformation;
  	
    String loadingFailureReason = Openssl.getLoadingFailureReason();
    if (loadingFailureReason != null) {
      throw new RuntimeException(loadingFailureReason);
    }
    
    cipher = Openssl.getInstance(transformation.getName());
    random = Utils.getSecureRandom(props);
  }

  @Override
  protected void finalize() throws Throwable {
    try {
      Closeable r = (Closeable) this.random;
      r.close();
    } catch (ClassCastException e) {
    }
    super.finalize();
  }

	@Override
	public CipherTransformation getTransformation() {
		return transformation;
	}

	@Override
	public void init(int mode, byte[] key, byte[] iv) throws IOException {
		Preconditions.checkNotNull(key);
    Preconditions.checkNotNull(iv);
		
		int cipherMode = Openssl.DECRYPT_MODE;
		if(mode == ENCRYPT_MODE)
			cipherMode = Openssl.ENCRYPT_MODE;
		
    cipher.init(cipherMode, key, iv);
	}

	@Override
	public int update(ByteBuffer inBuffer, ByteBuffer outBuffer) throws IOException {
		try {
      return cipher.update(inBuffer, outBuffer);
    } catch (Exception e) {
      throw new IOException(e);
    }
	}

	@Override
	public int doFinal(ByteBuffer inBuffer, ByteBuffer outBuffer) throws IOException {
		try {
			int n = cipher.update(inBuffer, outBuffer);
      return n + cipher.doFinal(outBuffer);
    } catch (Exception e) {
      throw new IOException(e);
    }
	}
  
  @Override
  public void generateSecureRandom(byte[] bytes) {
    random.nextBytes(bytes);
  }
  
}
