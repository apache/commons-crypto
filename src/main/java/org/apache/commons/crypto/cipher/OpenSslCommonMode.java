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

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;

/**
 * This class do the real work(Encryption/Decryption) for non-authenticated modes, such as CTR, CBC.
 * <p>
 * It will call the OpenSSL API to implement encryption/decryption
 */
class OpenSslCommonMode extends OpenSslFeedbackCipher {

    OpenSslCommonMode(long context, int algorithmMode, int padding) {
        super(context, algorithmMode, padding);
    }

    @Override
    public void init(int mode, byte[] key, AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
        this.cipherMode = mode;
        byte[] iv;
        if (params instanceof IvParameterSpec) {
            iv = ((IvParameterSpec) params).getIV();
        } else {
            // other AlgorithmParameterSpec is not supported now.
            throw new InvalidAlgorithmParameterException("Illegal parameters");
        }
        context = OpenSslNative.init(context, mode, algorithmMode, padding, key, iv);
    }

    @Override
    public int update(ByteBuffer input, ByteBuffer output) throws ShortBufferException {
        checkState();

        int len = OpenSslNative.update(context, input, input.position(),
                input.remaining(), output, output.position(),
                output.remaining());
        input.position(input.limit());
        output.position(output.position() + len);

        return len;
    }

    @Override
    public int update(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException {
        checkState();

        return OpenSslNative.updateByteArray(context, input, inputOffset,
                inputLen, output, outputOffset, output.length - outputOffset);
    }

    @Override
    public int doFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        checkState();

        int len = OpenSslNative.updateByteArray(context, input, inputOffset,
                inputLen, output, outputOffset, output.length - outputOffset);

        len += OpenSslNative.doFinalByteArray(context, output, outputOffset + len,
                output.length - outputOffset - len);

        return len;
    }

    @Override
    public int doFinal(ByteBuffer input, ByteBuffer output)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        checkState();

        int totalLen = 0;
        int len = OpenSslNative.update(context, input, input.position(),
                input.remaining(), output, output.position(), output.remaining());
        totalLen += len;

        input.position(input.limit());
        output.position(output.position() + len);

        len = OpenSslNative.doFinal(context, output, output.position(),
                output.remaining());
        totalLen += len;

        output.position(output.position() + len);

        return totalLen;
    }

    @Override
    public void updateAAD(byte[] aad) {
        throw new UnsupportedOperationException(
                "The underlying Cipher implementation "
                        + "does not support this method");
    }
}
