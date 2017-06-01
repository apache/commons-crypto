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
package org.apache.commons.crypto.cipher;

import org.apache.commons.crypto.utils.Utils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;

/**
 * This class represents a block cipher in one of its modes.
 */
abstract class OpenSslFeedbackCipher {

    protected long context = 0;
    protected int algorithmMode;
    protected int padding;

    protected int cipherMode = OpenSsl.DECRYPT_MODE;

    OpenSslFeedbackCipher(long context, int algorithmMode, int padding) {
        this.context = context;
        this.algorithmMode = algorithmMode;
        this.padding = padding;
    }

    abstract void init(int mode, byte[] key, AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException;

    abstract int update(ByteBuffer input, ByteBuffer output)
            throws ShortBufferException;

    abstract int update(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException;

    abstract int doFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException;

    abstract int doFinal(ByteBuffer input, ByteBuffer output) throws ShortBufferException,
            IllegalBlockSizeException, BadPaddingException;

    abstract void updateAAD(byte[] aad);

    public void clean() {
        if (context != 0) {
            OpenSslNative.clean(context);
            context = 0;
        }
    }

    public void checkState() {
        Utils.checkState(context != 0);
    }
}
