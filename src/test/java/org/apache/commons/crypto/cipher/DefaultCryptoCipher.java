/*
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

package org.apache.commons.crypto.cipher;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

/**
 * Tests default methods.
 */
public class DefaultCryptoCipher implements CryptoCipher {

    @Override
    public void close() throws IOException {
        // Simplest

    }

    @Override
    public int getBlockSize() {
        // Simplest
        return 0;
    }

    @Override
    public String getAlgorithm() {
        // Simplest
        return null;
    }

    @Override
    public void init(final int mode, final Key key, final AlgorithmParameterSpec params) throws InvalidKeyException, InvalidAlgorithmParameterException {
        // Simplest

    }

    @Override
    public int update(final ByteBuffer inBuffer, final ByteBuffer outBuffer) throws ShortBufferException {
        // Simplest
        return 0;
    }

    @Override
    public int update(final byte[] input, final int inputOffset, final int inputLen, final byte[] output, final int outputOffset) throws ShortBufferException {
        // Simplest
        return 0;
    }

    @Override
    public int doFinal(final ByteBuffer inBuffer, final ByteBuffer outBuffer) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        // Simplest
        return 0;
    }

    @Override
    public int doFinal(final byte[] input, final int inputOffset, final int inputLen, final byte[] output, final int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        // Simplest
        return 0;
    }

}
